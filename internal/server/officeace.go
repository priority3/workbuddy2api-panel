// officeace.go "oa:" realm 独立通道：OfficeAce（华为云 AgentArts 网关）转发。
//
// 与 WorkBuddy 池通道的关系：完全独立。OfficeAce 是单一静态凭证（Basic
// app_key/app_secret），没有多账号/冷却/粘性/轮换语义，因此不进 pool、
// 不参与 breaker/degrade/WAF 状态机，失败即原样透传上游状态码。
package server

import (
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/linguo2625469/workbuddy2api-panel/internal/officeace"
	"github.com/linguo2625469/workbuddy2api-panel/internal/usage"
)

// officeaceChat oa: 前缀模型的转发实现。调用点在 chatCompletions 解析出
// realm=="oa" 之后、进入 WorkBuddy 选号循环之前；body 为原始请求 JSON，
// bareModel 已剥离 "oa:" 前缀。
//
// 响应透传策略：上游本就是 OpenAI 兼容格式（含 SSE 流式），状态码、
// Content-Type 与 body 原样回写。流式经 chatStatsReader 抓末帧 usage
// （与 cn/global 通道同一统计口径），非流式解析响应体 usage 字段。
func (h *Handler) officeaceChat(w http.ResponseWriter, r *http.Request, body []byte, bareModel string, stream bool, st *chatStat) {
	oa := h.officeaceClient()
	if !oa.Enabled() {
		st.status = http.StatusServiceUnavailable
		st.outcome = "officeace_disabled"
		writeOpenAIError(w, http.StatusServiceUnavailable, "officeace_disabled",
			"model routed to officeace realm but officeace upstream is not configured")
		return
	}

	// 出站 model 重写为裸名（与 cn/global 通道同一协议：前缀是网关侧路由协议）。
	// 请求本就是裸名时不动 body。
	outBody := body
	if m := parseModelFromBody(body); m != "-" && m != bareModel {
		outBody = rewriteModel(body, bareModel)
	}

	started := time.Now()
	resp, err := oa.Chat(r.Context(), outBody, stream)
	if err != nil {
		if r.Context().Err() != nil {
			st.status = 499 // 客户端断连（日志口径，与主通道一致）
			st.outcome = "client_gone"
			return
		}
		st.status = http.StatusBadGateway
		st.outcome = "officeace_upstream_error"
		writeOpenAIError(w, http.StatusBadGateway, "upstream_error",
			"officeace upstream request failed: "+err.Error())
		return
	}
	defer resp.Body.Close()

	st.uid = "officeace"
	if resp.StatusCode != http.StatusOK {
		// 上游 4xx/5xx 原样透传（错误体已是 OpenAI error JSON 格式），
		// 不做冷却/轮换——单凭证通道没有"换一个"的选项。
		st.status = resp.StatusCode
		st.outcome = "officeace_upstream_status"
		relayHeader(w, resp.Header)
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, io.LimitReader(resp.Body, 1<<20))
		return
	}

	// 成功：透传 + 统计。
	st.status = http.StatusOK
	relayHeader(w, resp.Header)
	if stream {
		stats := newChatStatsReaderSince(resp.Body, started)
		w.WriteHeader(http.StatusOK)
		flusher, _ := w.(http.Flusher)
		buf := make([]byte, 16<<10)
		for {
			n, rerr := stats.Read(buf)
			if n > 0 {
				if _, werr := w.Write(buf[:n]); werr != nil {
					break
				}
				if flusher != nil {
					flusher.Flush()
				}
			}
			if rerr != nil {
				break // 含 io.EOF；上游中断时下游自然收到短流
			}
		}
		st.ttfb = stats.TTFB()
		if delta := stats.Usage(); delta.HasTotalTokens || delta.HasCompletionTokens || delta.HasPromptTokens {
			st.promptTokens = delta.PromptTokens
			st.completionTokens = delta.CompletionTokens
			st.totalTokens = delta.TotalTokens
			st.toks = int(delta.TotalTokens)
		}
		h.recordOfficeAceUsage(bareModel, stats, started)
		return
	}

	// 非流式：读完解析 usage 再回写。
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		st.status = http.StatusBadGateway
		st.outcome = "officeace_body_read_error"
		writeOpenAIError(w, http.StatusBadGateway, "upstream_error",
			"officeace upstream response read failed: "+err.Error())
		return
	}
	var parsed struct {
		Usage struct {
			PromptTokens     int64 `json:"prompt_tokens"`
			CompletionTokens int64 `json:"completion_tokens"`
			TotalTokens      int64 `json:"total_tokens"`
		} `json:"usage"`
	}
	_ = json.Unmarshal(raw, &parsed)
	st.promptTokens = parsed.Usage.PromptTokens
	st.completionTokens = parsed.Usage.CompletionTokens
	st.totalTokens = parsed.Usage.TotalTokens
	if parsed.Usage.TotalTokens > 0 || parsed.Usage.CompletionTokens > 0 || parsed.Usage.PromptTokens > 0 {
		st.toks = int(parsed.Usage.TotalTokens)
	}
	w.WriteHeader(http.StatusOK)
	w.Write(raw)
	h.recordOfficeAceUsageSync(bareModel, parsed.Usage, started)
}

// officeaceClient 返回当前生效的 OfficeAce 客户端（可被面板热替换）。
func (h *Handler) officeaceClient() *officeace.Client {
	h.oaMu.RLock()
	c := h.oaClient
	h.oaMu.RUnlock()
	return c
}

// OfficeAce 返回当前生效的 OfficeAce 客户端（面板状态/测试接口读取用；nil = 未启用）。
func (h *Handler) OfficeAce() *officeace.Client { return h.officeaceClient() }

// SetOfficeAce 热替换 OfficeAce 通道客户端（面板保存配置后调用）。
// 传 nil = 关闭通道（oa: 模型随即返回 503 officeace_disabled）。
// 已在处理中的请求仍用旧客户端跑完，不受影响。
func (h *Handler) SetOfficeAce(c *officeace.Client) {
	h.oaMu.Lock()
	h.oaClient = c
	h.oaMu.Unlock()
}

// relayHeader 透传对下游有意义的响应头（SSE 依赖 Content-Type 判流式）。
// 跳过 hop-by-hop 与长度类头（Go 按实际写入重算）。
func relayHeader(w http.ResponseWriter, src http.Header) {
	skip := map[string]bool{
		"Content-Length":    true,
		"Transfer-Encoding": true,
		"Connection":        true,
		"Keep-Alive":        true,
	}
	for k, vs := range src {
		if skip[k] {
			continue
		}
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
}

// recordOfficeAceUsage 流式路径的用量记录（从 chatStatsReader 取末帧 usage）。
// realm 记 "oa"、uid 记 "officeace"，与 WorkBuddy 池账号在用量视图中天然区分。
func (h *Handler) recordOfficeAceUsage(model string, stats *chatStatsReader, started time.Time) {
	if h.cfg.Usage == nil {
		return
	}
	delta := stats.Usage()
	has := delta.HasTotalTokens || delta.HasCompletionTokens || delta.HasPromptTokens
	if !has {
		return // 无 usage 帧：不虚增统计
	}
	delta.Model = model
	delta.HasLatencyMs = true
	delta.LatencyMs = time.Since(started).Milliseconds()
	if delta.HasCompletionTokens {
		if tps, ok := tokensPerSecond(delta.CompletionTokens,
			time.Duration(delta.LatencyMs)*time.Millisecond, stats.TTFB()); ok {
			delta.HasTokensPerSecond = true
			delta.TokensPerSecond = tps
		}
	}
	h.cfg.Usage.Add(time.Now(), "oa", "officeace", model, usage.Delta{
		PromptTokens:     delta.PromptTokens,
		HasPromptTokens:  delta.HasPromptTokens,
		CompletionTokens: delta.CompletionTokens,
		HasCompletion:    delta.HasCompletionTokens,
		TotalTokens:      delta.TotalTokens,
		HasTotal:         delta.HasTotalTokens,
		LatencyMs:        delta.LatencyMs,
		HasLatency:       true,
		TokensPerSecond:  delta.TokensPerSecond,
		HasTPS:           delta.HasTokensPerSecond,
	}, true)
}

// recordOfficeAceUsageSync 非流式路径的用量记录。
func (h *Handler) recordOfficeAceUsageSync(model string, u struct {
	PromptTokens     int64 `json:"prompt_tokens"`
	CompletionTokens int64 `json:"completion_tokens"`
	TotalTokens      int64 `json:"total_tokens"`
}, started time.Time) {
	if h.cfg.Usage == nil {
		return
	}
	has := u.PromptTokens > 0 || u.CompletionTokens > 0 || u.TotalTokens > 0
	if !has {
		return
	}
	h.cfg.Usage.Add(time.Now(), "oa", "officeace", model, usage.Delta{
		PromptTokens:     u.PromptTokens,
		HasPromptTokens:  u.PromptTokens > 0,
		CompletionTokens: u.CompletionTokens,
		HasCompletion:    u.CompletionTokens > 0,
		TotalTokens:      u.TotalTokens,
		HasTotal:         u.TotalTokens > 0,
		LatencyMs:        time.Since(started).Milliseconds(),
		HasLatency:       true,
	}, true)
}
