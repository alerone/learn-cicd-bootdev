package auth

import (
	"errors"
	"github.com/google/go-cmp/cmp"
	"net/http"
	"testing"
)

func TestGetApiKey(t *testing.T) {
	tests := map[string]struct {
		input http.Header
		want  string
		err   error
	}{
		"no auth header": {
			input: http.Header{
				"Api-Key": []string{"Bearer 66de1878-8dd2-4c72-a598-45ed6222c0ab"},
			},
			want: "",
			err:  ErrNoAuthHeaderIncluded,
		},
		"auth header included and is ok": {
			input: http.Header{
				"Authorization": []string{"ApiKey 66de1878-8dd2-4c72-a598-45ed6222c0ab"},
			},
			want: "66de1878-8dd2-4c72-a598-45ed6222c0ab",
			err:  nil,
		},
		"auth header malformed": {
			input: http.Header{
				"Authorization": []string{"Bearer ApiKey ApiKey 66de1878-8dd2-4c72-a598-45ed6222c0ab"},
			},
			want: "",
			err:  errors.New("malformed authorization header"),
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got, gotErr := GetAPIKey(tc.input)
			if gotErr != nil {
				if tc.err == nil {
					t.Fatalf("for input %v expected output %s and error encountered but error must be nil", tc.input, tc.want)
				} else if gotErr.Error() != tc.err.Error() {
					t.Fatalf("for input %v expected output %s and error encountered:\n\tgot error: %v but error must be: %v", tc.input, tc.want, gotErr, tc.err)
				}
			}
			diff := cmp.Diff(tc.want, got)
			if diff != "" {
				t.Fatal(diff)
			}
		})
	}
}
