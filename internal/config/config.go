// Package config loads and validates the runtime configuration of the
// whitelister from environment variables.
package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// Environment variable names. The camelCase names are kept for backward
// compatibility with existing Lambda deployments.
const (
	EnvIPRangesURL      = "amazonIPRangesURL"
	EnvRegion           = "awsRegion"
	EnvTableName        = "dynamoTableName"
	EnvParamName        = "previousDateParamStore"
	EnvSecurityGroupIDs = "securityGroupIDs"
	EnvServices         = "servicesToBeWhitelist"
	EnvPort             = "egressPort"
	EnvMaxRulesPerGroup = "maxRulesPerGroup"
)

// Defaults applied when the corresponding variable is unset.
const (
	DefaultIPRangesURL      = "https://ip-ranges.amazonaws.com/ip-ranges.json"
	DefaultTableName        = "whitelistedIPRanges"
	DefaultParamName        = "lastModifiedDateIPRanges"
	DefaultPort             = 443
	DefaultMaxRulesPerGroup = 50
)

// Config holds all settings required for a whitelisting run.
type Config struct {
	IPRangesURL      string
	Region           string // empty means "use the SDK default resolution chain"
	TableName        string
	ParamName        string
	SecurityGroupIDs []string
	Services         []string
	Port             int32
	MaxRulesPerGroup int
}

// Load reads the configuration from the process environment.
func Load() (Config, error) {
	return FromLookup(os.LookupEnv)
}

// FromLookup builds a Config using the provided lookup function, which makes
// the loader testable without mutating the process environment.
func FromLookup(lookup func(string) (string, bool)) (Config, error) {
	get := func(key, def string) string {
		if v, ok := lookup(key); ok && strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
		return def
	}

	cfg := Config{
		IPRangesURL:      get(EnvIPRangesURL, DefaultIPRangesURL),
		Region:           get(EnvRegion, ""),
		TableName:        get(EnvTableName, DefaultTableName),
		ParamName:        get(EnvParamName, DefaultParamName),
		SecurityGroupIDs: splitList(get(EnvSecurityGroupIDs, "")),
		Services:         splitList(strings.ToUpper(get(EnvServices, ""))),
	}

	var errs []error

	port, err := strconv.Atoi(get(EnvPort, strconv.Itoa(DefaultPort)))
	if err != nil || port < 1 || port > 65535 {
		errs = append(errs, fmt.Errorf("%s must be a port number between 1 and 65535", EnvPort))
	}
	cfg.Port = int32(port)

	maxRules, err := strconv.Atoi(get(EnvMaxRulesPerGroup, strconv.Itoa(DefaultMaxRulesPerGroup)))
	if err != nil || maxRules < 1 {
		errs = append(errs, fmt.Errorf("%s must be a positive integer", EnvMaxRulesPerGroup))
	}
	cfg.MaxRulesPerGroup = maxRules

	if len(cfg.SecurityGroupIDs) == 0 {
		errs = append(errs, fmt.Errorf("%s is required", EnvSecurityGroupIDs))
	}
	for _, id := range cfg.SecurityGroupIDs {
		if !strings.HasPrefix(id, "sg-") {
			errs = append(errs, fmt.Errorf("%s: %q is not a security group ID", EnvSecurityGroupIDs, id))
		}
	}
	if len(cfg.Services) == 0 {
		errs = append(errs, fmt.Errorf("%s is required", EnvServices))
	}

	if err := errors.Join(errs...); err != nil {
		return Config{}, fmt.Errorf("invalid configuration: %w", err)
	}
	return cfg, nil
}

// splitList splits a comma-separated value, trimming whitespace and dropping
// empty and duplicate entries while preserving order.
func splitList(s string) []string {
	var out []string
	seen := make(map[string]struct{})
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if _, dup := seen[part]; dup {
			continue
		}
		seen[part] = struct{}{}
		out = append(out, part)
	}
	return out
}
