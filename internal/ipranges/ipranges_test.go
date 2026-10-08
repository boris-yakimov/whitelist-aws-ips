package ipranges

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strings"
	"testing"
)

const sampleJSON = `{
  "syncToken": "1700000000",
  "createDate": "2026-10-01-12-00-00",
  "prefixes": [
    {"ip_prefix": "3.5.140.0/22",  "region": "ap-northeast-2", "service": "S3",          "network_border_group": "ap-northeast-2"},
    {"ip_prefix": "3.5.0.0/19",    "region": "us-east-1",      "service": "S3",          "network_border_group": "us-east-1"},
    {"ip_prefix": "52.95.0.0/16",  "region": "us-east-1",      "service": "AMAZON",      "network_border_group": "us-east-1"},
    {"ip_prefix": "52.219.4.0/24", "region": "us-east-1",      "service": "s3",          "network_border_group": "us-east-1"},
    {"ip_prefix": "15.0.0.0/8",    "region": "GLOBAL",         "service": "API_GATEWAY", "network_border_group": "GLOBAL"},
    {"ip_prefix": "15.177.0.0/18", "region": "GLOBAL",         "service": "API_GATEWAY", "network_border_group": "GLOBAL"}
  ]
}`

func TestFetch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, sampleJSON)
	}))
	defer srv.Close()

	doc, err := Fetch(context.Background(), srv.Client(), srv.URL)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if doc.CreateDate != "2026-10-01-12-00-00" || len(doc.Prefixes) != 6 {
		t.Errorf("unexpected document: %+v", doc)
	}
}

func TestFetchErrors(t *testing.T) {
	tests := map[string]http.HandlerFunc{
		"status":       func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "boom", http.StatusInternalServerError) },
		"invalid json": func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, "{not json") },
		"no date":      func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, `{"prefixes":[]}`) },
	}
	for name, h := range tests {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(h)
			defer srv.Close()
			if _, err := Fetch(context.Background(), srv.Client(), srv.URL); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestSummarize(t *testing.T) {
	doc := mustDoc(t)

	tests := []struct {
		name     string
		services []string
		bits     int
		want     []string
	}{
		{"s3 widened to /16, case-insensitive, deduplicated", []string{"S3"}, 16, []string{"3.5.0.0/16", "52.219.0.0/16"}},
		{"wider prefixes kept and contained ones dropped", []string{"api_gateway"}, 16, []string{"15.0.0.0/8"}},
		{"multiple services", []string{"S3", "AMAZON"}, 16, []string{"3.5.0.0/16", "52.95.0.0/16", "52.219.0.0/16"}},
		{"no widening at /32", []string{"S3"}, 32, []string{"3.5.0.0/19", "3.5.140.0/22", "52.219.4.0/24"}},
		{"unknown service", []string{"NOPE"}, 16, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Summarize(doc, tc.services, tc.bits)
			if err != nil {
				t.Fatalf("Summarize: %v", err)
			}
			if gs := toStrings(got); !slices.Equal(gs, tc.want) {
				t.Errorf("got %v, want %v", gs, tc.want)
			}
		})
	}
}

func TestSummarizeErrors(t *testing.T) {
	if _, err := Summarize(&Document{}, []string{"S3"}, 33); err == nil {
		t.Error("expected error for invalid prefix length")
	}
	bad := &Document{Prefixes: []Prefix{{IPPrefix: "not-an-ip", Service: "S3"}}}
	if _, err := Summarize(bad, []string{"S3"}, 16); err == nil {
		t.Error("expected error for invalid prefix")
	}
}

func mustDoc(t *testing.T) *Document {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, strings.TrimSpace(sampleJSON))
	}))
	defer srv.Close()
	doc, err := Fetch(context.Background(), srv.Client(), srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	return doc
}

func toStrings(ps []netip.Prefix) []string {
	if len(ps) == 0 {
		return nil
	}
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = p.String()
	}
	return out
}
