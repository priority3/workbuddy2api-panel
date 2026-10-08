// officeace_test.go "oa:" realm 独立通道的端到端行为。
package server

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/linguo2625469/workbuddy2api-panel/internal/auth"
	"github.com/linguo2625469/workbuddy2api-panel/internal/officeace"
)

// newOfficeaceUpstream 起 fake 华为云网关，校验 Basic 鉴权与出站 model 裸名，
// 返回固定 OpenAI 响应（含 usage）。
func newOfficeaceUpstream(t *testing.T, wantKey, wantSecret string, calls *int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*calls++
		if r.URL.Path != "/v2/chat/completions" {
			t.Errorf("path=%s want /v2/chat/completions", r.URL.Path)
		}
		wantAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte(wantKey+":"+wantSecret))
		if r.Header.Get("Authorization") != wantAuth {
			t.Errorf("auth=%q want Basic pair", r.Header.Get("Authorization"))
		}
		var peek struct {
			Model  string `json:"model"`
			Stream bool   `json:"stream"`
		}
		_ = json.NewDecoder(r.Body).Decode(&peek)
		if strings.Contains(peek.Model, ":") {
			t.Errorf("outbound model=%q must be bare (prefix stripped)", peek.Model)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id":      "chatcmpl-test",
			"object":  "chat.completion",
			"model":   peek.Model,
			"choices": []any{map[string]any{"index": 0, "message": map[string]any{"role": "assistant", "content": "OK"}}},
			"usage":   map[string]any{"prompt_tokens": 3, "completion_tokens": 1, "total_tokens": 4},
		})
	}))
}

func officeaceTestClient(base string) *officeace.Client {
	return officeace.New(officeace.Config{BaseURL: base, AppKey: "k-test", AppSecret: "s-test", TimeoutSeconds: 10})
}

// TestOfficeAceChatPassthrough oa: 前缀请求不进 WorkBuddy 池，直接透传转发，
// 出站剥前缀、Basic 换签、usage 计入统计。
func TestOfficeAceChatPassthrough(t *testing.T) {
	var calls int
	ts := newOfficeaceUpstream(t, "k-test", "s-test", &calls)
	defer ts.Close()

	h := NewHandler(Config{OfficeAce: officeaceTestClient(ts.URL)})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("POST", "/v1/chat/completions",
		bytes.NewBufferString(`{"model":"oa:glm-5.3","messages":[{"role":"user","content":"hi"}]}`)))
	if rec.Code != http.StatusOK {
		t.Fatalf("code=%d body=%s", rec.Code, rec.Body)
	}
	if calls != 1 {
		t.Fatalf("upstream calls=%d want 1", calls)
	}
	var resp struct {
		Model string `json:"model"`
		Usage struct {
			TotalTokens int64 `json:"total_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Model != "glm-5.3" {
		t.Errorf("model=%q want glm-5.3", resp.Model)
	}
	if resp.Usage.TotalTokens != 4 {
		t.Errorf("usage.total_tokens=%d want 4", resp.Usage.TotalTokens)
	}
}

// TestOfficeAceDisabled 未配置客户端时 oa: 模型返回 503（不落到 WorkBuddy 池）。
func TestOfficeAceDisabled(t *testing.T) {
	h := NewHandler(Config{})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("POST", "/v1/chat/completions",
		bytes.NewBufferString(`{"model":"oa:glm-5.3","messages":[]}`)))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("code=%d want 503 body=%s", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), "officeace_disabled") {
		t.Errorf("body missing officeace_disabled: %s", rec.Body)
	}
}

// TestOfficeAceModelsListing 已启用时 /v1/models 追加 "oa:" 前缀名单。
func TestOfficeAceModelsListing(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v2/models" {
			t.Errorf("path=%s want /v2/models", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"object": "list",
			"data":   []any{map[string]any{"id": "glm-5.3"}, map[string]any{"id": "Kimi-K2.6"}},
		})
	}))
	defer ts.Close()

	// /v1/models 主链路（cn/global 名单）依赖池与 upstream 实例；fake 即空名单。
	h := NewHandler(Config{
		Pool:      testPoolWith(&auth.Auth{UID: "u1", AccessToken: "at1", ExpiresAt: 9999999999}),
		Upstream:  newFakeUpstream(t, func(string) (int, string, bool) { return 200, "", true }),
		OfficeAce: officeaceTestClient(ts.URL),
	})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/v1/models", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("code=%d", rec.Code)
	}
	var resp struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	seen := map[string]bool{}
	for _, m := range resp.Data {
		seen[m.ID] = true
	}
	for _, want := range []string{"oa:glm-5.3", "oa:Kimi-K2.6"} {
		if !seen[want] {
			t.Errorf("models missing %q; got %v", want, seen)
		}
	}
}
