package panel

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/linguo2625469/workbuddy2api-panel/internal/officeace"
)

// fakeOfficeAce 起一个最小 OpenAI 兼容网关：只认 k1:s1 这一对 Basic 凭证，
// /v2/models 返回两个模型 id。用来验证面板测试接口的"提交值优先 + 缺失项
// 补齐当前生效值"语义，不依赖真实华为云。
func fakeOfficeAce(t *testing.T) (*httptest.Server, *int) {
	t.Helper()
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != "k1" || pass != "s1" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		calls++
		if strings.HasSuffix(r.URL.Path, "/models") {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"data":[{"id":"glm-5.2"},{"id":"deepseek-v3"}]}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)
	return srv, &calls
}

// TestOfficeAceStatusEndpoint 状态接口：未装配通道时 enabled=false 且不报错
//（面板要能正常渲染"未启用"，不能因为没配就整页 500）；装配后回显网关地址。
func TestOfficeAceStatusEndpoint(t *testing.T) {
	_, _ = fakeOfficeAce(t)

	get := func(cfg Config) map[string]any {
		p := New(cfg)
		req := httptest.NewRequest("GET", "/panel/api/officeace", nil)
		req.Header.Set("Authorization", "Bearer test-key")
		rec := httptest.NewRecorder()
		p.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("code=%d body=%s", rec.Code, rec.Body.String())
		}
		var got map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatal(err)
		}
		return got
	}

	// 1) 未装配：enabled=false，接口仍 200（页面照常渲染）。
	got := get(Config{APIKey: "test-key"})
	if got["enabled"] != false {
		t.Fatalf("unconfigured: enabled=%v want false", got["enabled"])
	}

	// 2) 已装配：回显归一化后的网关地址（不含任何密钥字段）。
	oa := officeace.New(officeace.Config{BaseURL: "gw.example.com", AppKey: "k1", AppSecret: "s1"})
	if oa == nil {
		t.Fatal("client should be built")
	}
	got = get(Config{APIKey: "test-key", OfficeAceClient: func() *officeace.Client { return oa }})
	if got["enabled"] != true {
		t.Fatalf("configured: enabled=%v want true", got["enabled"])
	}
	if got["base_url"] != "https://gw.example.com/v2" {
		t.Fatalf("base_url=%v want normalized https://gw.example.com/v2", got["base_url"])
	}
	if _, leaked := got["app_key"]; leaked {
		t.Fatal("status endpoint must not echo credentials")
	}
}

// TestOfficeAceTestEndpoint 连通性测试接口三态：
// 未配置凭证 → ok:false（探测结果不是接口错误，HTTP 仍 200）；
// 凭证不对 → ok:false + 上游原因；凭证正确 → ok:true + 模型数。
func TestOfficeAceTestEndpoint(t *testing.T) {
	srv, calls := fakeOfficeAce(t)

	post := func(cfg Config, body string) map[string]any {
		p := New(cfg)
		req := httptest.NewRequest("POST", "/panel/api/officeace/test", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer test-key")
		rec := httptest.NewRecorder()
		p.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("code=%d body=%s", rec.Code, rec.Body.String())
		}
		var got map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatal(err)
		}
		return got
	}

	// 1) 什么都没配：ok=false + 可操作的错误文案。
	got := post(Config{APIKey: "test-key"}, `{}`)
	if got["ok"] != false {
		t.Fatalf("unconfigured: ok=%v want false", got["ok"])
	}
	if _, has := got["error"]; !has {
		t.Fatal("unconfigured: want error message")
	}

	// 2) 提交一组错误凭证：ok=false，且不替换生效客户端（下一条断言依赖此）。
	got = post(Config{APIKey: "test-key"}, `{"base_url":"`+srv.URL+`","app_key":"k1","app_secret":"wrong"}`)
	if got["ok"] != false {
		t.Fatalf("bad secret: ok=%v want false (%v)", got["ok"], got["error"])
	}

	// 3) 提交完整正确凭证：ok=true + 模型数。
	got = post(Config{APIKey: "test-key"}, `{"base_url":"`+srv.URL+`","app_key":"k1","app_secret":"s1"}`)
	if got["ok"] != true {
		t.Fatalf("good creds: ok=%v err=%v", got["ok"], got["error"])
	}
	if got["models"] != float64(2) {
		t.Fatalf("models=%v want 2", got["models"])
	}

	// 4) 部分填写：只提交 app_key，secret 从**当前生效客户端**补齐——
	//    "只换 key / 只改地址"时不会因为缺另一半而必然失败。
	cur := officeace.New(officeace.Config{BaseURL: srv.URL, AppKey: "k1", AppSecret: "s1"})
	before := *calls
	got = post(Config{APIKey: "test-key", OfficeAceClient: func() *officeace.Client { return cur }},
		`{"app_key":"k1"}`)
	if got["ok"] != true {
		t.Fatalf("partial fill: ok=%v err=%v", got["ok"], got["error"])
	}
	if *calls <= before {
		t.Fatal("partial fill: upstream was not contacted")
	}

	// 5) body 为空 = 测当前生效配置。
	got = post(Config{APIKey: "test-key", OfficeAceClient: func() *officeace.Client { return cur }}, ``)
	if got["ok"] != true {
		t.Fatalf("empty body: ok=%v err=%v", got["ok"], got["error"])
	}
}
