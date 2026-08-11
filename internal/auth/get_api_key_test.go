package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name      string
		headerVal string
		noHeader  bool
		wantKey   string
		wantErr   error
	}{
		{
			name:      "valid header",
			headerVal: "ApiKey abc123",
			wantKey:   "abc123",
		},
		{
			name:     "no header",
			noHeader: true,
			wantErr:  ErrNoAuthHeaderIncluded,
		},
		{
			name:      "wrong prefix",
			headerVal: "Bearer abc123",
			wantErr:   errors.New("malformed authorization header"),
		},
		{
			name:      "missing key part",
			headerVal: "ApiKey",
			wantErr:   errors.New("malformed authorization header"),
		},
		{
			name:      "empty string",
			headerVal: "",
			wantErr:   ErrNoAuthHeaderIncluded,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := http.Header{}
			if !tt.noHeader && tt.headerVal != "" {
				h.Set("Authorization", tt.headerVal)
			}

			got, err := GetAPIKey(h)

			if tt.wantErr != nil {
				if err == nil {
					t.Fatalf("want err %q, got nil", tt.wantErr)
				}
				if errors.Is(tt.wantErr, ErrNoAuthHeaderIncluded) {
					if !errors.Is(err, ErrNoAuthHeaderIncluded) {
						t.Fatalf("want ErrNoAuthHeaderIncluded, got %q", err)
					}
				} else if err.Error() != tt.wantErr.Error() {
					t.Fatalf("want err %q, got %q", tt.wantErr, err)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			if got != tt.wantKey {
				t.Fatalf("want key %q, got %q", tt.wantKey, got)
			}
		})
	}
}
