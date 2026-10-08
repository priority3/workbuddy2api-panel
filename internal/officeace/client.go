// Package officeace 提供 OfficeAce（华为云 AgentArts ModelArts 网关）的
// OpenAI 兼容上游客户端。
//
// 背景：OfficeAce 桌面端登录华为云后，其"额度"实际是华为云侧签发的一对
// model_app_key / model_app_secret，配合 OpenAI 兼容网关使用：
//
//	POST {base}/chat/completions
//	Authorization: Basic base64(app_key:app_secret)
//
// 该鉴权是静态 Basic（非 STS 临时凭证、非 DPoP），不需要续期链路，因此
// 服务端只需保存三元组 {base_url, app_key, app_secret} 即可长期转发。
//
// 本包刻意做薄：不做错误分类/冷却/轮换（那是 WorkBuddy 账号池的语义，
// OfficeAce 通道没有多账号概念），只负责出站请求与响应的透传，统计由
// server 层的 chatStatsReader 在透传流上完成。
package officeace

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// DefaultBaseURL 官方 ModelArts 网关。带实例编号（modelgw-0004），不同账号
// 可能不同——配置里 base_url 显式给出时以配置为准；此处仅作缺省兜底，
// 与 OfficeAce 桌面端当前下发的 model_api_url_base 一致。
const DefaultBaseURL = "https://modelgw-0004.officeace.cn-southwest-2.huaweicloud-agentarts.com/v2"

// Config 客户端配置。
type Config struct {
	// BaseURL 上游网关地址；空 = DefaultBaseURL。尾斜杠与 /v2 后缀自动归一化
	//（与桌面端 normalizeBaseUrl 行为一致：没有 /v2 就补上）。
	BaseURL string
	// AppKey / AppSecret 模型网关 Basic 鉴权对（来自桌面端凭证
	// modelInfo.model_auth_info）。两者均必填。
	AppKey    string
	AppSecret string
	// TimeoutSeconds 单请求上限（含 SSE 全程）。<=0 回落 300s。
	// SSE 流式响应活跃吐数据时受 http.Transport ResponseHeaderTimeout 之外的
	// 整体 ctx 控制——这里用整体超时而不是首字节超时，语义从简（OfficeAce
	// 通道无池化抢号，超时即失败返回，无罚号副作用）。
	TimeoutSeconds int
}

// Client OfficeAce 上游客户端。零值不可用，经 New 构造。
type Client struct {
	baseURL string
	auth    string // 预计算的 "Basic xxx"
	http    *http.Client

	mu              sync.Mutex
	models          []string
	modelsFetchedAt time.Time
}

// New 构造客户端。appKey/appSecret 缺失时返回 nil（调用方按"未启用"处理）。
func New(cfg Config) *Client {
	if strings.TrimSpace(cfg.AppKey) == "" || strings.TrimSpace(cfg.AppSecret) == "" {
		return nil
	}
	base := strings.TrimSpace(cfg.BaseURL)
	if base == "" {
		base = DefaultBaseURL
	}
	base = strings.TrimRight(base, "/")
	if !strings.HasSuffix(base, "/v2") {
		base += "/v2"
	}
	timeout := time.Duration(cfg.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 300 * time.Second
	}
	return &Client{
		baseURL: base,
		auth: "Basic " + base64.StdEncoding.EncodeToString(
			[]byte(strings.TrimSpace(cfg.AppKey)+":"+strings.TrimSpace(cfg.AppSecret))),
		http: &http.Client{Timeout: timeout},
	}
}

// Enabled 报告客户端是否可用（New 返回 nil 即未启用）。
func (c *Client) Enabled() bool { return c != nil }

// BaseURL 返回归一化后的网关地址（观测/日志用）。
func (c *Client) BaseURL() string { return c.baseURL }

// Models 返回上游模型 id 列表，1 小时缓存；失败回退上次成功结果，
// 从未成功则返回 nil（/v1/models 里该域自然为空，不编造）。
func (c *Client) Models(ctx context.Context) []string {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	cached, ok := c.models, time.Since(c.modelsFetchedAt) < time.Hour
	c.mu.Unlock()
	if ok {
		return cached
	}
	ids, err := c.fetchModels(ctx)
	if err != nil {
		return nil // 保留旧缓存，下次到期再试
	}
	c.mu.Lock()
	c.models, c.modelsFetchedAt = ids, time.Now()
	c.mu.Unlock()
	return ids
}

func (c *Client) fetchModels(ctx context.Context) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/models", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", c.auth)
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
		return nil, fmt.Errorf("officeace models: status %d", resp.StatusCode)
	}
	var parsed struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&parsed); err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(parsed.Data))
	for _, m := range parsed.Data {
		if id := strings.TrimSpace(m.ID); id != "" {
			ids = append(ids, id)
		}
	}
	return ids, nil
}

// Chat 向 {base}/chat/completions 出站转发 body（原样 JSON），返回上游响应。
// 调用方负责关闭 resp.Body 并把响应透传给下游（本包不做协议转换——上游本就
// 是 OpenAI 兼容格式，含 SSE 流式）。
//
// 出站统一剥掉客户端侧的分块/长度头，由 net/http 按实际内容重算；Authorization
// 恒为本通道 Basic（客户端传来的 Bearer 一律丢弃，不透传凭据）。
func (c *Client) Chat(ctx context.Context, body []byte, stream bool) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/chat/completions", strings.NewReader(string(body)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", c.auth)
	req.Header.Set("Content-Type", "application/json")
	if stream {
		req.Header.Set("Accept", "text/event-stream")
	}
	return c.http.Do(req)
}
