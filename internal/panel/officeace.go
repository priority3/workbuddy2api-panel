// officeace.go 面板侧 OfficeAce 通道接口：状态回显与连通性测试。
//
// 存在的理由：OfficeAce 凭证（app_key/app_secret）是从桌面端加密文件里导出的
// 长字符串，手抄进 config.json 极易出错，且错了只能从日志里看出来。面板给一个
// 「填完立刻测」的入口，把"配置对不对"这件事在保存前就闭环。
package panel

import (
	"encoding/json"
	"io"
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
