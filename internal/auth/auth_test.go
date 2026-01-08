package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name       string
		headerVal  string
		wantKey    string
		wantErr    error // compare directly only when it's a known sentinel error
		wantErrMsg string
	}{
		{
			name:      "success",
			headerVal: "ApiKey abc123",
			wantKey:   "abc123",
		},
		{
			name:      "missing Authorization header returns sentinel error",
			headerVal: "",
			wantErr:   ErrNoAuthHeaderIncluded,
		},
		{
			name:       "malformed - wrong scheme",
			headerVal:  "Bearer abc123",
			wantErrMsg: "malformed authorization header",
		},
		{
			name:       "malformed - no key part",
			headerVal:  "ApiKey",
			wantErrMsg: "malformed authorization header",
		},
		{
			name:      "malformed - extra spaces causes empty key with current implementation",
			headerVal: "ApiKey  abc123", // strings.Split produces ["ApiKey", "", "abc123"], so key becomes ""
			wantKey:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := make(http.Header)
			if tt.headerVal != "" {
				h.Set("Authorization", tt.headerVal)
			}

			gotKey, gotErr := GetAPIKey(h)

			if tt.wantErr != nil {
				if gotErr != tt.wantErr {
					t.Fatalf("expected error %v, got %v", tt.wantErr, gotErr)
				}
				return
			}

			if tt.wantErrMsg != "" {
				if gotErr == nil {
					t.Fatalf("expected error %q, got nil", tt.wantErrMsg)
				}
				if gotErr.Error() != tt.wantErrMsg {
					t.Fatalf("expected error %q, got %q", tt.wantErrMsg, gotErr.Error())
				}
				return
			}

			if gotErr != nil {
				t.Fatalf("expected nil error, got %v", gotErr)
			}
			if gotKey != tt.wantKey {
				t.Fatalf("expected key %q, got %q", tt.wantKey, gotKey)
			}
		})
	}
}
