// officeace.go 面板侧 OfficeAce 通道接口：状态回显与连通性测试。
//
// 存在的理由：OfficeAce 凭证（app_key/app_secret）是从桌面端加密文件里导出的
// 长字符串，手抄进 config.json 极易出错，且错了只能从日志里看出来。面板给一个
// 「填完立刻测」的入口，把"配置对不对"这件事在保存前就闭环。
package panel

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/linguo2625469/workbuddy2api-panel/internal/officeace"
)

// officeaceStatus 回显当前生效的通道状态（不回传任何密钥原文——面板页面
// 不该成为密钥泄露面，只给「配没配 / 连的哪个网关 / 有几个模型」）。
func (p *Panel) officeaceStatus(w http.ResponseWriter, r *http.Request) {
	oa := p.officeaceClient()
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":       true,
		"enabled":  oa.Enabled(),
		"base_url": oa.BaseURL(),
		// 模型数：命中 1h 缓存，不因状态刷新触发上游调用
		//（真要探测走 officeaceTest，语义分明）。
		"models": len(oa.Models(r.Context())),
	})
}

// officeaceTest 连通性测试：强制拉一次上游 /v2/models（绕过 1h 缓存）。
//
// body 可为空（测当前生效配置），也可带 {base_url, app_key, app_secret}
// 测一组尚未保存的凭证——这样用户填完能先验证再决定要不要保存。
// 失败一律返回 200 + ok:false（这是探测结果不是接口错误），错误文案直接透出上游原因。
func (p *Panel) officeaceTest(w http.ResponseWriter, r *http.Request) {
	raw, err := io.ReadAll(io.LimitReader(r.Body, 1<<16))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "read body: "+err.Error())
		return
	}
	var in struct {
		BaseURL   string `json:"base_url"`
		AppKey    string `json:"app_key"`
		AppSecret string `json:"app_secret"`
	}
	_ = json.Unmarshal(raw, &in)

	oa := p.officeaceClient()
	// 三者任一非空 → 按提交值临时构造（不落盘、不替换生效客户端）。
	if strings.TrimSpace(in.AppKey) != "" || strings.TrimSpace(in.AppSecret) != "" || strings.TrimSpace(in.BaseURL) != "" {
		key, secret := in.AppKey, in.AppSecret
		// 部分填写时补齐当前生效值：常见的用法是「只改网关地址」或「只换 secret」，
		// 不补齐会因缺另一半而必然失败，用户会误判成"新值不对"。
		if strings.TrimSpace(key) == "" || strings.TrimSpace(secret) == "" {
			curKey, curSecret := oa.Creds()
			if strings.TrimSpace(key) == "" {
				key = curKey
			}
			if strings.TrimSpace(secret) == "" {
				secret = curSecret
			}
		}
		base := in.BaseURL
		if strings.TrimSpace(base) == "" {
			base = oa.BaseURL()
		}
		oa = officeace.New(officeace.Config{BaseURL: base, AppKey: key, AppSecret: secret, TimeoutSeconds: 30})
	}
	if !oa.Enabled() {
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":    false,
			"error": "未配置凭证（config officeace.app_key/app_secret 或环境变量 OFFICEACE_APP_KEY/OFFICEACE_APP_SECRET）",
		})
		return
	}

	start := time.Now()
	ids, err := oa.Probe(r.Context())
	latency := time.Since(start).Milliseconds()
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"ok": false, "latency_ms": latency, "error": err.Error(),
		})
		return
	}
	// 只回前 8 个模型 id 做样本，全量在 /v1/models 里看。
	sample := ids
	if len(sample) > 8 {
		sample = sample[:8]
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "latency_ms": latency, "models": len(ids), "sample": sample, "base_url": oa.BaseURL(),
	})
}

// officeaceLoginStart 发起端到端授权：向华为云要 state 并生成登录页地址。
// 返回 {ok, authorize_url, state}——前端弹小窗打开 authorize_url，随后按
// state 轮询 login/poll，与桌面端 LoginPage 的轮询节奏一致（1.5s）。
func (p *Panel) officeaceLoginStart(w http.ResponseWriter, r *http.Request) {
	if p.cfg.OfficeAceAuthorizer == nil {
		writeErr(w, http.StatusNotImplemented, "officeace authorize not available")
		return
	}
	authorizeURL, state, err := p.cfg.OfficeAceAuthorizer.Start(r.Context())
	if err != nil {
		// 上游不可达等真错误：502，前端 toast 展示原因。
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	log.Printf("panel: officeace 授权已发起（state=%s...）", maskTail(state, 6))
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "authorize_url": authorizeURL, "state": state,
	})
}

// officeaceLoginPoll 轮询授权结果。
//
// 三种返回（HTTP 恒 200，授权状态不是接口错误）：
//   - {ok:true, done:true}                    完成并已落盘热生效
//   - {ok:true, done:false}                   用户还没登录完，继续轮
//   - {ok:false, error}                       授权失败（换 token 失败/未开通/会话过期），前端应停止轮询
func (p *Panel) officeaceLoginPoll(w http.ResponseWriter, r *http.Request) {
	if p.cfg.OfficeAceAuthorizer == nil || p.cfg.OfficeAceAuthorizeSave == nil {
		writeErr(w, http.StatusNotImplemented, "officeace authorize not available")
		return
	}
	state := strings.TrimSpace(r.URL.Query().Get("state"))
	if state == "" {
		writeErr(w, http.StatusBadRequest, "缺少 state 参数")
		return
	}
	creds, err := p.cfg.OfficeAceAuthorizer.Poll(r.Context(), state)
	switch {
	case errors.Is(err, officeace.ErrPending):
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "done": false})
		return
	case err != nil:
		log.Printf("panel: officeace 授权失败: %v", err)
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	if err := p.cfg.OfficeAceAuthorizeSave(*creds); err != nil {
		log.Printf("panel: officeace 凭证落盘失败: %v", err)
		writeErr(w, http.StatusInternalServerError, "凭证已获取但写入配置失败: "+err.Error())
		return
	}
	log.Printf("panel: officeace 授权完成 user=%s base=%s（凭证已写入配置并热生效）",
		creds.UserName, maskTail(creds.BaseURL, 8))
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "done": true,
		"base_url": creds.BaseURL,
		"user":     creds.UserName,
	})
}

// maskTail 日志脱敏：只露尾部几字符便于对账，不泄露全文。
func maskTail(s string, n int) string {
	if len(s) <= n {
		return strings.Repeat("*", len(s))
	}
	return "..." + s[len(s)-n:]
}
