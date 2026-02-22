package password

import (
	"testing"
)

func TestGeneratePasswordFromLines(t *testing.T) {
	tests := []struct {
		name         string
		lines        []string
		loginURI     string
		loginFrom    string
		wantPassword string
		wantTOT      string
	}{
		{
			name:         "simple password and notes",
			lines:        []string{"mysecret", "some note", "more"},
			loginURI:     "example.com",
			loginFrom:    "alice",
			wantPassword: "mysecret",
			wantTOT:      "",
		},
		{
			name:         "password with otp",
			lines:        []string{"pass123", "otpauth://totp/FAKE?secret=ABC"},
			loginURI:     "example.org",
			loginFrom:    "bob",
			wantPassword: "pass123",
			wantTOT:      "otpauth://totp/FAKE?secret=ABC",
		},
		{
			name:         "only otp line",
			lines:        []string{"otpauth://totp/ONLY?secret=XYZ"},
			loginURI:     "only.example",
			loginFrom:    "carol",
			wantPassword: "",
			wantTOT:      "otpauth://totp/ONLY?secret=XYZ",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var p Entry
			gotLines := GeneratePasswordFromLines(tc.lines, &p, tc.loginURI, tc.loginFrom)
			if gotLines != len(tc.lines) {
				t.Fatalf("expected total_lines %d, got %d", len(tc.lines), gotLines)
			}
			if p.LoginPassword != tc.wantPassword {
				t.Fatalf("LoginPassword = %q; want %q", p.LoginPassword, tc.wantPassword)
			}
			if p.LoginTOT != tc.wantTOT {
				t.Fatalf("LoginTOT = %q; want %q", p.LoginTOT, tc.wantTOT)
			}
			// name composition
			wantName := tc.loginURI + " " + tc.loginFrom
			if p.Name != wantName {
				t.Fatalf("Name = %q; want %q", p.Name, wantName)
			}
			// if password present, SHA1 should be set
			if tc.wantPassword != "" {
				if p.SHA1 == "" {
					t.Fatalf("expected SHA1 to be set for password %q", tc.wantPassword)
				}
			}
			// if tot present, TOTPSHA1 should be set
			if tc.wantTOT != "" {
				if p.TOTPSHA1 == "" {
					t.Fatalf("expected TOTPSHA1 to be set for tot %q", tc.wantTOT)
				}
			}
		})
	}
}
