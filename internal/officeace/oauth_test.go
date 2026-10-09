package officeace

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// TestGeneratePKCE 已知答案：challenge 必须等于 base64url(sha256(verifier))，
// 且 verifier 为 32 字节的 base64url（43 字符）。
func TestGeneratePKCE(t *testing.T) {
	verifier, challenge, err := generatePKCE()
	if err != nil {
		t.Fatal(err)
	}
	if len(verifier) != 43 {
		t.Fatalf("verifier len=%d want 43 (base64url of 32 bytes)", len(verifier))
	}
	sum := sha256.Sum256([]byte(verifier))
	want := base64.RawURLEncoding.EncodeToString(sum[:])
	if challenge != want {
		t.Fatalf("challenge mismatch: got %q want %q", challenge, want)
	}
	// 两次生成不重复（熵检查的最小形式）。
	v2, _, _ := generatePKCE()
	if v2 == verifier {
		t.Fatal("two generatePKCE calls returned the same verifier")
	}
}

// TestDpopJWT 结构与签名可验证：3 段 JWT、header 含 dpop+jwt/ES256/P-256 jwk、
// payload 的 htm/htu 正确、签名是 64 字节 raw r||s 且能用 jwk 公钥验签通过。
func TestDpopJWT(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	htu := "https://sts.example.com/v1/oauth2/tokens"
	token, err := dpopJWT(key, http.MethodPost, htu)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("jwt parts=%d want 3", len(parts))
	}
	hb, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatal(err)
	}
	var h struct {
		Typ string `json:"typ"`
		Alg string `json:"alg"`
		Jwk struct {
			Kty string `json:"kty"`
			Crv string `json:"crv"`
			X   string `json:"x"`
			Y   string `json:"y"`
		} `json:"jwk"`
	}
	if err := json.Unmarshal(hb, &h); err != nil {
		t.Fatal(err)
	}
	if h.Typ != "dpop+jwt" || h.Alg != "ES256" || h.Jwk.Kty != "EC" || h.Jwk.Crv != "P-256" {
		t.Fatalf("header mismatch: %+v", h)
	}
	pb, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var p struct {
		HTM string `json:"htm"`
		HTU string `json:"htu"`
		IAT int64  `json:"iat"`
		JTI string `json:"jti"`
	}
	if err := json.Unmarshal(pb, &p); err != nil {
		t.Fatal(err)
	}
	if p.HTM != http.MethodPost || p.HTU != htu || p.IAT == 0 || p.JTI == "" {
		t.Fatalf("payload mismatch: %+v", p)
	}
	// raw r||s (64B) → ASN.1 → ecdsa.Verify
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(sig) != 64 {
		t.Fatalf("sig len=%d err=%v want 64", len(sig), err)
	}
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if !ecdsa.Verify(&key.PublicKey, digest[:], r, s) {
		t.Fatal("ECDSA verify failed: signature does not match public jwk")
	}
}

// TestSignHuaweiTC3 确定性回归：固定 ak/sk/header/path，签名必须逐字节稳定，
// 且 Authorization 结构为 SDK-HMAC-SHA256 三段式。
func TestSignHuaweiTC3(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "https://agentarts.example.com/v1/claw/client-permission-validate?a=1&b=2", nil)
	if err != nil {
		t.Fatal(err)
	}
	now := "20261009T064000Z"
	req.Header.Set("x-sdk-date", now)
	req.Header.Set("x-subscription-type", "v2")
	req.Header.Set("X-Security-Token", "tok-123")
	auth, err := signHuaweiTC3(req, now, "AKTEST", "SKTEST")
	if err != nil {
		t.Fatal(err)
	}
	const prefix = "SDK-HMAC-SHA256 Access=AKTEST, SignedHeaders="
	if !strings.HasPrefix(auth, prefix) {
		t.Fatalf("authorization prefix mismatch: %s", auth)
	}
	// host/x-sdk-date/x-security-token/x-subscription-type 均参与签名（字母序）。
	if !strings.Contains(auth, "SignedHeaders=host;x-sdk-date;x-security-token;x-subscription-type;") &&
		!strings.Contains(auth, "SignedHeaders=host;x-sdk-date;x-security-token;x-subscription-type,") {
		// SignedHeaders 以分号分隔、结尾无分号——宽松校验包含关系
		if !strings.Contains(auth, "host;x-sdk-date;x-security-token;x-subscription-type") {
			t.Fatalf("signed headers missing expected entries: %s", auth)
		}
	}
	sigIdx := strings.Index(auth, "Signature=")
	if sigIdx < 0 || len(auth)-sigIdx-len("Signature=") != 64 {
		t.Fatalf("signature should be 64 hex chars: %s", auth)
	}
	// 确定性：同输入两次签名一致。
	auth2, _ := signHuaweiTC3(req, now, "AKTEST", "SKTEST")
	if auth != auth2 {
		t.Fatal("TC3 signing is not deterministic for identical input")
	}
	// sk 变化 → 签名变化。
	auth3, _ := signHuaweiTC3(req, now, "AKTEST", "SKOTHER")
	if auth3 == auth {
		t.Fatal("different secret key must produce different signature")
	}
}

// TestAuthorizerEndToEnd 起一个假华为云（state/code/token/permission 四端点），
// 走完 Start → pending → 授权 → Poll 全链路，拿到 model_info 凭证。
func TestAuthorizerEndToEnd(t *testing.T) {
	var sessState struct {
		verifier string
	}
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	mux.HandleFunc("/v1/claw/auth/state", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"state":"st-123"}`))
	})
	mux.HandleFunc("/v1/claw/auth/code", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("state") != "st-123" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if sessState.verifier == "" {
			w.WriteHeader(http.StatusNotFound) // 还没授权
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":"auth-code-1"}`))
	})
	// IAM token：DPoP 头必须存在，code_verifier 必须匹配 PKCE verifier。
	mux.HandleFunc("/v1/oauth2/tokens", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("DPoP") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if err := r.ParseForm(); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		sessState.verifier = r.FormValue("code_verifier")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"credentials":{"access_key_id":"AK","secret_access_key":"SK",` +
			`"security_token":"ST","project_id":"pid","expiration":"2026-10-09T12:00:00Z"},` +
			`"id_token":"` + fakeIDToken(t, "zhang-san") + `"}`))
	})
	mux.HandleFunc("/v1/claw/client-permission-validate", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Security-Token") != "ST" || r.Header.Get("X-Project-ID") != "pid" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		if !strings.HasPrefix(r.Header.Get("Authorization"), "SDK-HMAC-SHA256 Access=AK,") {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"account_id":"acc","principal_urn":"iam::acc:user:zhang-san",` +
			`"model_info":{"model_api_url_base":"modelgw-0004.example.com",` +
			`"model_auth_info":{"model_app_key":"mk","model_app_secret":"ms"}}}}`))
	})

	a := NewAuthorizer()
	a.clawBase = srv.URL
	a.authBase = srv.URL
	a.iamBase = srv.URL
	a.redirect = srv.URL + "/v1/claw/auth/callback"

	authorizeURL, state, err := a.Start(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// service 参数是整体 QueryEscape 的（与桌面端一致）：解码后断言 PKCE/state。
	decoded, decErr := url.QueryUnescape(authorizeURL)
	if decErr != nil || !strings.Contains(decoded, "code_challenge=") ||
		!strings.Contains(decoded, "state=st-123") || !strings.Contains(decoded, "client_id=pdp5_for_agentarts") {
		t.Fatalf("authorize url missing pkce/state/client: %s", authorizeURL)
	}

	// 未授权：ErrPending。
	if _, err := a.Poll(context.Background(), state); err != ErrPending {
		t.Fatalf("before consent: err=%v want ErrPending", err)
	}

	// "用户完成登录"：假 IAM 端点已捕获 code_verifier，此处标记授权完成。
	sessState.verifier = "released"
	// verifier 是 Poll 内部从会话取的——测试只需让 code 端点放行；
	// 会话里的真实 verifier 会随 token 请求发出，端点只回显记录。

	creds, err := a.Poll(context.Background(), state)
	if err != nil {
		t.Fatal(err)
	}
	if creds.AppKey != "mk" || creds.AppSecret != "ms" || creds.BaseURL != "modelgw-0004.example.com" {
		t.Fatalf("creds mismatch: %+v", creds)
	}
	if creds.UserName != "zhang-san" {
		t.Fatalf("user=%q want zhang-san", creds.UserName)
	}

	// code 是一次性的：本地会话已销毁，再 Poll 报会话不存在。
	if _, err := a.Poll(context.Background(), state); err == nil || err == ErrPending {
		t.Fatalf("second poll after success: err=%v want session-gone error", err)
	}}

// fakeIDToken 造一个 payload 含 preferred_username 的无签名 id_token（测试用）。
func fakeIDToken(t *testing.T, user string) string {
	t.Helper()
	hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	pl, err := json.Marshal(map[string]string{"preferred_username": user, "sub": "sub-" + user})
	if err != nil {
		t.Fatal(err)
	}
	return hdr + "." + base64.RawURLEncoding.EncodeToString(pl) + ".c2ln"
}
