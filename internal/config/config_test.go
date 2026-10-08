package config

import (
	"strings"
	"testing"
)

func lookup(env map[string]string) func(string) (string, bool) {
	return func(k string) (string, bool) {
		v, ok := env[k]
		return v, ok
	}
}

func TestFromLookupDefaults(t *testing.T) {
	cfg, err := FromLookup(lookup(map[string]string{
		EnvSecurityGroupIDs: "sg-1, sg-2,,sg-1",
		EnvServices:         "s3,api_gateway",
	}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got, want := strings.Join(cfg.SecurityGroupIDs, ","), "sg-1,sg-2"; got != want {
		t.Errorf("SecurityGroupIDs = %q, want %q", got, want)
	}
	if got, want := strings.Join(cfg.Services, ","), "S3,API_GATEWAY"; got != want {
		t.Errorf("Services = %q, want %q", got, want)
	}
	if cfg.IPRangesURL != DefaultIPRangesURL {
		t.Errorf("IPRangesURL = %q, want default", cfg.IPRangesURL)
	}
	if cfg.TableName != DefaultTableName || cfg.ParamName != DefaultParamName {
		t.Errorf("unexpected table/param defaults: %q / %q", cfg.TableName, cfg.ParamName)
	}
	if cfg.Port != DefaultPort || cfg.MaxRulesPerGroup != DefaultMaxRulesPerGroup {
		t.Errorf("unexpected port/max defaults: %d / %d", cfg.Port, cfg.MaxRulesPerGroup)
	}
	if cfg.Region != "" {
		t.Errorf("Region = %q, want empty", cfg.Region)
	}
}

func TestFromLookupOverrides(t *testing.T) {
	cfg, err := FromLookup(lookup(map[string]string{
		EnvSecurityGroupIDs: "sg-1",
		EnvServices:         "S3",
		EnvRegion:           "eu-central-1",
		EnvPort:             "8443",
		EnvMaxRulesPerGroup: "100",
		EnvTableName:        "t",
		EnvParamName:        "p",
		EnvIPRangesURL:      "https://example.com/ip.json",
	}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Region != "eu-central-1" || cfg.Port != 8443 || cfg.MaxRulesPerGroup != 100 ||
		cfg.TableName != "t" || cfg.ParamName != "p" || cfg.IPRangesURL != "https://example.com/ip.json" {
		t.Errorf("overrides not applied: %+v", cfg)
	}
}

func TestFromLookupErrors(t *testing.T) {
	tests := map[string]struct {
		env  map[string]string
		want []string
	}{
		"missing required": {
			env:  map[string]string{},
			want: []string{EnvSecurityGroupIDs + " is required", EnvServices + " is required"},
		},
		"bad group id": {
			env:  map[string]string{EnvSecurityGroupIDs: "sg-1,foo", EnvServices: "S3"},
			want: []string{`"foo" is not a security group ID`},
		},
		"bad port": {
			env:  map[string]string{EnvSecurityGroupIDs: "sg-1", EnvServices: "S3", EnvPort: "70000"},
			want: []string{EnvPort},
		},
		"bad max rules": {
			env:  map[string]string{EnvSecurityGroupIDs: "sg-1", EnvServices: "S3", EnvMaxRulesPerGroup: "0"},
			want: []string{EnvMaxRulesPerGroup},
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := FromLookup(lookup(tc.env))
			if err == nil {
				t.Fatal("expected error")
			}
			for _, w := range tc.want {
				if !strings.Contains(err.Error(), w) {
					t.Errorf("error %q does not contain %q", err, w)
				}
			}
		})
	}
}
