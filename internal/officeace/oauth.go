// oauth.go OfficeAce 的端到端授权（华为云 OAuth2 + PKCE + DPoP），无桌面端参与。
//
// 链路（逆向自 OfficeAce 桌面端 huawei-oauth.js / api/dist/index.js，与桌面端
// 完全同源）：
//
//	POST {claw}/v1/claw/auth/state        → 云端签发 state
//	（浏览器打开华为云统一登录页，登录后 code 存在云端，按 state 关联）
//	GET  {claw}/v1/claw/auth/code?state   → 拿到授权 code
//	POST {iam}/v1/oauth2/tokens           → code 换 IAM 临时凭证（DPoP + PKCE）
//	GET  {claw}/v1/claw/client-permission-validate
//	                                      → model_info（TC3-HMAC-SHA256 签名）
//	    ↳ model_info.model_api_url_base / model_auth_info.model_app_key|model_app_secret
//	                                      → 回调方落盘 + 热加载
//
// 关键常量（client_id / redirect_uri / 各 base）与桌面端一致——redirect_uri 指向
// 华为云自己托管的 callback，这是本流程可以服务端独立完成的前提：凭证不落本地
// 浏览器，云端按 state 发放 code，谁持有 PKCE verifier + DPoP 私钥谁能换 token。
package officeace

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	// DefaultAuthBase 华为云统一登录页。
	DefaultAuthBase = "https://auth.huaweicloud.com"
	// DefaultIAMBase IAM OAuth2 token 端点（STS）。
	DefaultIAMBase = "https://sts.cn-north-4.myhuaweicloud.com"
	// DefaultClawBase AgentArts 服务端（state 签发 / code 发放 / 权限校验）。
	DefaultClawBase = "https://agentarts.cn-southwest-2.myhuaweicloud.com"

	// oauthClientID 与桌面端一致（不可改：redirect_uri 白名单绑定该 client）。
	oauthClientID = "pdp5_for_agentarts"

	authorizeTTL = 10 * time.Minute // state 有效期（云端侧亦有，超时须重发起）
	pollInterval = 0                // 轮询节奏由前端控制，这里不做 sleep
)

// ErrPending 授权尚未完成（用户还没在浏览器里登录/同意）。
var ErrPending = errors.New("officeace: authorization pending")

// AuthorizedCreds 授权成功后提取的模型网关凭证（写入 config officeace 段并热加载）。
type AuthorizedCreds struct {
	BaseURL   string // model_info.model_api_url_base（可能无 scheme，交 Client.New 归一化）
	AppKey    string // model_info.model_auth_info.model_app_key
	AppSecret string // model_info.model_auth_info.model_app_secret
	UserName  string // 华为云账号名（展示用）
}

// Authorizer 端到端授权会话管理。零值不可用，经 NewAuthorizer 构造。
type Authorizer struct {
	clawBase string
	authBase string
	iamBase  string
	redirect string
	http     *http.Client

	mu      sync.Mutex
	pending map[string]*authSession
}

type authSession struct {
	codeVerifier string
	dpopKey      *ecdsa.PrivateKey
	createdAt    time.Time
}

// NewAuthorizer 构造授权器（直连，不走环境代理，与 Client 同口径）。
func NewAuthorizer() *Authorizer {
	return &Authorizer{
		clawBase:  DefaultClawBase,
		authBase:  DefaultAuthBase,
		iamBase:   DefaultIAMBase,
		redirect:  DefaultClawBase + "/v1/claw/auth/callback",
		http:      &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{Proxy: nil}},
		pending:   map[string]*authSession{},
	}
}

// Start 发起一次授权：向云端要 state，本地生成 PKCE 与 DPoP 密钥对，
// 返回用户需要在浏览器打开的华为云登录页地址。
func (a *Authorizer) Start(ctx context.Context) (authorizeURL, state string, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.clawBase+"/v1/claw/auth/state", nil)
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := a.http.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("请求云端 state 失败: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<10))
	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("获取 state 失败: status %d, body %.200s", resp.StatusCode, raw)
	}
	var parsed struct {
		State string `json:"state"`
		Data  struct {
			State string `json:"state"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return "", "", fmt.Errorf("解析 state 响应失败: %w", err)
	}
	state = strings.TrimSpace(parsed.State)
	if state == "" {
		state = strings.TrimSpace(parsed.Data.State)
	}
	if state == "" {
		return "", "", errors.New("云端未返回 state")
	}

	verifier, challenge, err := generatePKCE()
	if err != nil {
		return "", "", err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("生成 DPoP 密钥失败: %w", err)
	}

	a.mu.Lock()
	a.pruneLocked()
	a.pending[state] = &authSession{codeVerifier: verifier, dpopKey: key, createdAt: time.Now()}
	a.mu.Unlock()
	inner := a.authBase + "/authui/v1/oauth2/authorize?" + url.Values{
		"client_id":              {oauthClientID},
		"code_challenge":         {challenge},
		"code_challenge_method":  {"SHA-256"},
		"state":                  {state},
		"scope":                  {"openid"},
		"redirect_uri":           {a.redirect},
		"response_type":          {"code"},
	}.Encode()
	// 与桌面端一致的登录页包装（背景图参数仅影响观感，缺省也出登录框）。
	authorizeURL = a.authBase + "/authui/login.html?service=" + url.QueryEscape(inner)
	return authorizeURL, state, nil
}

// Poll 查询授权结果。用户尚未完成登录返回 ErrPending；完成则完成整条交换链
// 并返回模型网关凭证。会话过期/不存在返回错误（前端应重新发起 Start）。
func (a *Authorizer) Poll(ctx context.Context, state string) (*AuthorizedCreds, error) {
	state = strings.TrimSpace(state)
	a.mu.Lock()
	sess := a.pending[state]
	if sess != nil && time.Since(sess.createdAt) > authorizeTTL {
		delete(a.pending, state)
		sess = nil
	}
	a.mu.Unlock()
	if sess == nil {
		return nil, errors.New("授权会话不存在或已过期，请重新发起")
	}

	// 1) 云端查 code（未授权时 404/无 code 字段 → pending）。
	code, err := a.fetchAuthCode(ctx, state)
	if err != nil {
		return nil, err
	}

	// 2) code 换 IAM 临时凭证（一次性：无论成败都销毁本地会话，与桌面端一致）。
	a.mu.Lock()
	delete(a.pending, state)
	a.mu.Unlock()

	cred, err := a.exchangeToken(ctx, code, sess)
	if err != nil {
		return nil, err
	}

	// 3) 权限校验拿 model_info（已开通场景；未开通需要走邀请码开通，这里直接报可读错误）。
	creds, err := a.fetchModelInfo(ctx, cred)
	if err != nil {
		return nil, err
	}
	creds.UserName = cred.userName
	return creds, nil
}

// fetchAuthCode 轮询云端 code。语义对齐桌面端代理 /api/login/oauth/poll：
// 非 200 或响应无 code 都视为 pending（登录中/取消/过期统一处理，前端继续轮询）。
func (a *Authorizer) fetchAuthCode(ctx context.Context, state string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		a.clawBase+"/v1/claw/auth/code?state="+url.QueryEscape(state), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := a.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("轮询云端授权结果失败: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<10))
	if resp.StatusCode != http.StatusOK {
		return "", ErrPending
	}
	var parsed struct {
		Code string `json:"code"`
		Data struct {
			Code string `json:"code"`
		} `json:"data"`
	}
	_ = json.Unmarshal(raw, &parsed)
	code := strings.TrimSpace(parsed.Code)
	if code == "" {
		code = strings.TrimSpace(parsed.Data.Code)
	}
	if code == "" {
		return "", ErrPending
	}
	return code, nil
}

// iamCredential IAM OAuth2 token 响应归一化后的临时凭证。
type iamCredential struct {
	access     string
	secret     string
	secToken   string
	projectID  string
	expiration string
	userName   string
}

// exchangeToken 用授权码换 IAM 临时凭证：DPoP 签名的 form POST。
// 响应 credentials.access_key_id / secret_access_key / security_token / project_id / expiration。
func (a *Authorizer) exchangeToken(ctx context.Context, code string, sess *authSession) (*iamCredential, error) {
	tokenURL := a.iamBase + "/v1/oauth2/tokens"
	dpop, err := dpopJWT(sess.dpopKey, http.MethodPost, tokenURL)
	if err != nil {
		return nil, fmt.Errorf("生成 DPoP 失败: %w", err)
	}
	form := url.Values{
		"client_id":     {oauthClientID},
		"code":          {code},
		"code_verifier": {sess.codeVerifier},
		"grant_type":    {"authorization_code"},
		"redirect_uri":  {a.redirect},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("DPoP", dpop)
	resp, err := a.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("IAM token 请求失败: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("授权码交换失败: status %d, body %.300s", resp.StatusCode, raw)
	}
	var parsed struct {
		Credentials struct {
			AccessKeyID     string `json:"access_key_id"`
			SecretAccessKey string `json:"secret_access_key"`
			SecurityToken   string `json:"security_token"`
			ProjectID       string `json:"project_id"`
			Expiration      string `json:"expiration"`
		} `json:"credentials"`
		IDToken string `json:"id_token"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, fmt.Errorf("解析 IAM token 响应失败: %w", err)
	}
	c := &parsed.Credentials
	if c.AccessKeyID == "" || c.SecretAccessKey == "" {
		return nil, errors.New("IAM token 响应缺少临时凭证")
	}
	return &iamCredential{
		access:    c.AccessKeyID,
		secret:    c.SecretAccessKey,
		secToken:  c.SecurityToken,
		projectID: c.ProjectID,
		expiration: c.Expiration,
		userName:  userNameFromIDToken(parsed.IDToken),
	}, nil
}

// fetchModelInfo 权限校验（华为云 TC3 签名）拿 model_info。
// 未开通服务的账号返回可读错误（桌面端此场景走邀请码开通页）。
func (a *Authorizer) fetchModelInfo(ctx context.Context, cred *iamCredential) (*AuthorizedCreds, error) {
	endpoint := a.clawBase + "/v1/claw/client-permission-validate"
	headers := map[string]string{
		"x-subscription-type": "v2",
	}
	if cred.secToken != "" {
		headers["X-Security-Token"] = cred.secToken
	}
	if cred.projectID != "" {
		headers["X-Project-ID"] = cred.projectID
	}
	req, err := signedGetRequest(ctx, a.http, endpoint, headers, cred.access, cred.secret)
	if err != nil {
		return nil, err
	}
	resp, err := a.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("权限校验请求失败: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 256<<10))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("权限校验失败: status %d, body %.300s", resp.StatusCode, raw)
	}
	var top struct {
		Data struct {
			ModelInfo json.RawMessage `json:"model_info"`
		} `json:"data"`
		Result struct {
			ModelInfo json.RawMessage `json:"model_info"`
		} `json:"result"`
		ModelInfo json.RawMessage `json:"model_info"`
	}
	if err := json.Unmarshal(raw, &top); err != nil {
		return nil, fmt.Errorf("解析权限校验响应失败: %w", err)
	}
	mi := top.ModelInfo
	if len(mi) == 0 {
		mi = top.Data.ModelInfo
	}
	if len(mi) == 0 {
		mi = top.Result.ModelInfo
	}
	if len(mi) == 0 || string(mi) == "null" {
		return nil, errors.New("账号已登录，但尚未开通 OfficeAce 服务（桌面端需在开通页完成开通后再试）")
	}
	var info struct {
		ModelAPIURLBase string `json:"model_api_url_base"`
		ModelAuthInfo   struct {
			ModelAppKey    string `json:"model_app_key"`
			ModelAppSecret string `json:"model_app_secret"`
		} `json:"model_auth_info"`
	}
	if err := json.Unmarshal(mi, &info); err != nil {
		return nil, fmt.Errorf("解析 model_info 失败: %w", err)
	}
	if info.ModelAuthInfo.ModelAppKey == "" || info.ModelAuthInfo.ModelAppSecret == "" {
		return nil, errors.New("model_info 缺少 model_app_key/model_app_secret，无法接入")
	}
	return &AuthorizedCreds{
		BaseURL:   strings.TrimSpace(info.ModelAPIURLBase),
		AppKey:    strings.TrimSpace(info.ModelAuthInfo.ModelAppKey),
		AppSecret: strings.TrimSpace(info.ModelAuthInfo.ModelAppSecret),
	}, nil
}

// pruneLocked 清理过期会话（调用方持锁）。会话量小（面板手动发起）， O(n) 足够。
func (a *Authorizer) pruneLocked() {
	now := time.Now()
	for s, sess := range a.pending {
		if now.Sub(sess.createdAt) > authorizeTTL {
			delete(a.pending, s)
		}
	}
}

// signedGetRequest 构造带华为云 TC3 签名头的 GET 请求。
func signedGetRequest(ctx context.Context, client *http.Client, rawURL string, headers map[string]string, ak, sk string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC().Format("20060102T150405Z")
	req.Header.Set("x-sdk-date", now)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	auth, err := signHuaweiTC3(req, now, ak, sk)
	if err != nil {
		return nil, fmt.Errorf("生成 TC3 签名失败: %w", err)
	}
	req.Header.Set("Authorization", auth)
	return req, nil
}

// signHuaweiTC3 华为云 SDK-HMAC-SHA256 请求签名（与华为 SDK Signer 同口径）。
// 只签 Authorization 之外我们显式设置的 header（host/x-sdk-date/content-type/
// x-project-id/x-security-token/x-subscription-type），按字母序。
func signHuaweiTC3(req *http.Request, sdkDate, ak, sk string) (string, error) {
	u := req.URL
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	// CanonicalQueryString：key 排序、RFC3986 编码（空格→%20）。
	q := u.Query()
	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var cqs strings.Builder
	for i, k := range keys {
		if i > 0 {
			cqs.WriteByte('&')
		}
		vals := q[k]
		sort.Strings(vals)
		for _, v := range vals {
			cqs.WriteString(uriEncode(k))
			cqs.WriteByte('=')
			cqs.WriteString(uriEncode(v))
		}
	}
	// 参与签名的 header（不含 Authorization）。
	signNames := []string{"host", "x-sdk-date"}
	if ct := req.Header.Get("Content-Type"); ct != "" {
		signNames = append(signNames, "content-type")
	}
	for _, h := range []string{"x-project-id", "x-security-token", "x-subscription-type"} {
		if req.Header.Get(h) != "" {
			signNames = append(signNames, h)
		}
	}
	sort.Strings(signNames)
	var ch, sh strings.Builder
	for _, h := range signNames {
		var v string
		if h == "host" {
			v = u.Host
		} else {
			v = strings.TrimSpace(req.Header.Get(h))
		}
		ch.WriteString(h + ":" + v + "\n")
		sh.WriteString(h + ";")
	}
	signedHeaders := strings.TrimSuffix(sh.String(), ";")

	bodyHash := sha256.Sum256(nil)
	canonical := strings.Join([]string{
		req.Method,
		path,
		cqs.String(),
		ch.String(),
		signedHeaders,
		hex.EncodeToString(bodyHash[:]),
	}, "\n")
	sum := sha256.Sum256([]byte(canonical))
	stringToSign := "SDK-HMAC-SHA256\n" + sdkDate + "\n" + hex.EncodeToString(sum[:])
	mac := hmac.New(sha256.New, []byte(sk))
	mac.Write([]byte(stringToSign))
	sig := hex.EncodeToString(mac.Sum(nil))
	return "SDK-HMAC-SHA256 Access=" + ak + ", SignedHeaders=" + signedHeaders + ", Signature=" + sig, nil
}

// uriEncode RFC3986 严格编码（华为云规范要求空格→%20、保留字全编码）。
func uriEncode(s string) string {
	const hexDigits = "0123456789ABCDEF"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9',
			c == '-', c == '_', c == '.', c == '~':
			b.WriteByte(c)
		default:
			b.WriteByte('%')
			b.WriteByte(hexDigits[c>>4])
			b.WriteByte(hexDigits[c&0xF])
		}
	}
	return b.String()
}

// generatePKCE 标准 S256：verifier = base64url(32B)，challenge = base64url(sha256(verifier))。
func generatePKCE() (verifier, challenge string, err error) {
	raw := make([]byte, 32)
	if _, err = rand.Read(raw); err != nil {
		return "", "", err
	}
	verifier = base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

// dpopJWT ES256 DPoP proof（header.typ=dpop+jwt，payload htm/htu/iat/jti，
// 签名为 raw r||s，与 Node webcrypto subtle 输出一致）。
func dpopJWT(key *ecdsa.PrivateKey, htm, htu string) (string, error) {
	pub := key.PublicKey
	if pub.Curve != elliptic.P256() {
		return "", errors.New("DPoP key must be P-256")
	}
	x := make([]byte, 32)
	y := make([]byte, 32)
	pub.X.FillBytes(x)
	pub.Y.FillBytes(y)
	header, err := json.Marshal(map[string]any{
		"typ": "dpop+jwt",
		"alg": "ES256",
		"jwk": map[string]string{"kty": "EC", "crv": "P-256", "x": base64.RawURLEncoding.EncodeToString(x), "y": base64.RawURLEncoding.EncodeToString(y)},
	})
	if err != nil {
		return "", err
	}
	jti := make([]byte, 16)
	if _, err = rand.Read(jti); err != nil {
		return "", err
	}
	payload, err := json.Marshal(map[string]any{
		"htm": htm,
		"htu": htu,
		"iat": time.Now().Unix(),
		"jti": hex.EncodeToString(jti),
	})
	if err != nil {
		return "", err
	}
	signingInput := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		return "", err
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// userNameFromIDToken 从 id_token 的 preferred_username / name / sub 提取展示名。
func userNameFromIDToken(idToken string) string {
	parts := strings.Split(idToken, ".")
	if len(parts) < 2 {
		return ""
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var claims struct {
		Sub               string `json:"sub"`
		PreferredUsername string `json:"preferred_username"`
		Name              string `json:"name"`
	}
	if err := json.Unmarshal(raw, &claims); err != nil {
		return ""
	}
	if claims.PreferredUsername != "" {
		return claims.PreferredUsername
	}
	if claims.Name != "" {
		return claims.Name
	}
	return claims.Sub
}
