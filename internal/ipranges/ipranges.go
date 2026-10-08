// Package ipranges downloads and processes the published AWS IP address
// ranges (https://docs.aws.amazon.com/vpc/latest/userguide/aws-ip-ranges.html).
package ipranges

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"slices"
	"strings"
)

// maxDocumentSize bounds the response body to protect against unexpectedly
// large or malicious payloads. The real document is a few MiB.
const maxDocumentSize = 64 << 20

// Document is the subset of ip-ranges.json used by this project.
type Document struct {
	SyncToken  string   `json:"syncToken"`
	CreateDate string   `json:"createDate"`
	Prefixes   []Prefix `json:"prefixes"`
}

// Prefix is a single IPv4 entry of ip-ranges.json.
type Prefix struct {
	IPPrefix           string `json:"ip_prefix"`
	Region             string `json:"region"`
	Service            string `json:"service"`
	NetworkBorderGroup string `json:"network_border_group"`
}

// Fetch downloads and decodes the IP ranges document from url.
func Fetch(ctx context.Context, client *http.Client, url string) (*Document, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("download %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download %s: unexpected status %s", url, resp.Status)
	}

	var doc Document
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxDocumentSize)).Decode(&doc); err != nil {
		return nil, fmt.Errorf("decode %s: %w", url, err)
	}
	if doc.CreateDate == "" {
		return nil, errors.New("decode ip ranges: document has no createDate")
	}
	return &doc, nil
}

// Summarize returns the de-duplicated, sorted set of IPv4 CIDRs for the given
// services, widened to at most maxBits (e.g. 16 for /16 supernets). Prefixes
// that are already wider than maxBits are kept as-is, and any CIDR fully
// contained in another result is dropped.
//
// Service names are matched case-insensitively.
func Summarize(doc *Document, services []string, maxBits int) ([]netip.Prefix, error) {
	if maxBits < 0 || maxBits > 32 {
		return nil, fmt.Errorf("invalid prefix length /%d", maxBits)
	}

	wanted := make(map[string]struct{}, len(services))
	for _, s := range services {
		wanted[strings.ToUpper(s)] = struct{}{}
	}

	unique := make(map[netip.Prefix]struct{})
	for _, p := range doc.Prefixes {
		if _, ok := wanted[strings.ToUpper(p.Service)]; !ok {
			continue
		}
		prefix, err := netip.ParsePrefix(p.IPPrefix)
		if err != nil || !prefix.Addr().Is4() {
			return nil, fmt.Errorf("invalid IPv4 prefix %q for service %s", p.IPPrefix, p.Service)
		}
		if prefix.Bits() > maxBits {
			prefix, _ = prefix.Addr().Prefix(maxBits)
		} else {
			prefix = prefix.Masked()
		}
		unique[prefix] = struct{}{}
	}

	// Sort widest first so containment can be checked against already-kept entries.
	candidates := make([]netip.Prefix, 0, len(unique))
	for p := range unique {
		candidates = append(candidates, p)
	}
	slices.SortFunc(candidates, func(a, b netip.Prefix) int {
		return cmp.Or(cmp.Compare(a.Bits(), b.Bits()), a.Addr().Compare(b.Addr()))
	})

	var result []netip.Prefix
	for _, c := range candidates {
		if !slices.ContainsFunc(result, func(r netip.Prefix) bool { return r.Contains(c.Addr()) }) {
			result = append(result, c)
		}
	}

	slices.SortFunc(result, func(a, b netip.Prefix) int {
		return cmp.Or(a.Addr().Compare(b.Addr()), cmp.Compare(a.Bits(), b.Bits()))
	})
	return result, nil
}
