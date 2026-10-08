package main

import "testing"

// TestBuildOfficeAce 构造函数的三条分支：开关关 → nil（通道关闭）；凭证齐全 →
// 客户端可用；config 里没凭证但环境变量有 → 照样可用。
//
// 第三条是关键：saveConfig 热改时复用同一函数，"环境变量注入凭证 + 面板改配置"
// 的组合才不会因为重建而丢凭证（热改路径与启动路径必须同规则）。
func TestBuildOfficeAce(t *testing.T) {
	// 1) 开关关闭：无论有没有凭证都不建客户端。
	if c := buildOfficeAce(Config{}); c != nil {
		t.Fatalf("disabled: got %v want nil", c)
	}

	// 2) 开关开 + 凭证齐全。
	cfg := Config{}
	cfg.OfficeAce.Enabled = true
	cfg.OfficeAce.AppKey = "k"
	cfg.OfficeAce.AppSecret = "s"
	if c := buildOfficeAce(cfg); c == nil || !c.Enabled() {
		t.Fatalf("enabled with creds: got nil/disabled")
	}

	// 3) 开关开 + config 无凭证 + 环境变量兜底。
	t.Setenv("OFFICEACE_APP_KEY", "ek")
	t.Setenv("OFFICEACE_APP_SECRET", "es")
	cfg2 := Config{}
	cfg2.OfficeAce.Enabled = true
	c := buildOfficeAce(cfg2)
	if c == nil || !c.Enabled() {
		t.Fatalf("enabled with env creds: got nil/disabled")
	}
	if key, secret := c.Creds(); key != "ek" || secret != "es" {
		t.Fatalf("env fallback: creds=%q/%q want ek/es", key, secret)
	}

	// 4) 开关开但完全没凭证 → nil（网关侧按"未启用"处理，oa: 请求回 503）。
	t.Setenv("OFFICEACE_APP_KEY", "")
	t.Setenv("OFFICEACE_APP_SECRET", "")
	cfg3 := Config{}
	cfg3.OfficeAce.Enabled = true
	if c := buildOfficeAce(cfg3); c != nil {
		t.Fatalf("enabled without creds: got %v want nil", c)
	}
}
