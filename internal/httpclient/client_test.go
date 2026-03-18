package httpclient

import "testing"

func TestBuildURL(t *testing.T) {
	tests := []struct {
		domain string
		https  bool
		uri    string
		want   string
	}{
		{"example.com", false, "", "http://example.com"},
		{"example.com", true, "", "https://example.com"},
		{"example.com", false, "api/v1", "http://example.com/api/v1"},
		{"example.com", true, "/path", "https://example.com/path"},
	}

	for _, tt := range tests {
		got := BuildURL(tt.domain, tt.https, tt.uri)
		if got != tt.want {
			t.Errorf("BuildURL(%q, %v, %q) = %q, want %q",
				tt.domain, tt.https, tt.uri, got, tt.want)
		}
	}
}
