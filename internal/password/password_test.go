package password

import (
	"bytes"
	"io"
	"log"
	"os"
	"strings"
	"testing"
)

func captureOutput(f func()) string {
	oldOut := os.Stdout
	oldErr := os.Stderr
	oldLog := log.Writer()

	r, w, _ := os.Pipe()
	os.Stdout = w
	os.Stderr = w
	log.SetOutput(w)

	f()

	w.Close()
	var buf bytes.Buffer
	io.Copy(&buf, r)

	os.Stdout = oldOut
	os.Stderr = oldErr
	log.SetOutput(oldLog)
	return buf.String()
}

func TestCheckUniqueOTP(t *testing.T) {
	tests := []struct {
		name          string
		pwds          []Entry
		wantDuplicate bool
	}{
		{
			name: "no duplicates",
			pwds: []Entry{
				{Name: "a", LoginTOT: "otp1", TOTPSHA1: "h1"},
				{Name: "b", LoginTOT: "otp2", TOTPSHA1: "h2"},
			},
			wantDuplicate: false,
		},
		{
			name: "duplicate otp",
			pwds: []Entry{
				{Name: "a", LoginTOT: "otp1", TOTPSHA1: "h"},
				{Name: "b", LoginTOT: "otp1", TOTPSHA1: "h"},
			},
			wantDuplicate: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			out := captureOutput(func() { CheckUniqueOTP(&tc.pwds) })
			found := strings.Contains(out, "Duplicate OTP found")
			if found != tc.wantDuplicate {
				t.Fatalf("checkUniqueOTP() found duplicate=%v; want %v; output=%q", found, tc.wantDuplicate, out)
			}
		})
	}
}

func TestCheckUniquePasswords(t *testing.T) {
	tests := []struct {
		name          string
		pwds          []Entry
		wantDuplicate bool
	}{
		{
			name: "no duplicates",
			pwds: []Entry{
				{Name: "a", LoginPassword: "p1", SHA1: "s1"},
				{Name: "b", LoginPassword: "p2", SHA1: "s2"},
			},
			wantDuplicate: false,
		},
		{
			name: "duplicate password",
			pwds: []Entry{
				{Name: "a", LoginPassword: "p", SHA1: "s"},
				{Name: "b", LoginPassword: "p", SHA1: "s"},
			},
			wantDuplicate: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			out := captureOutput(func() { CheckUniquePasswords(&tc.pwds) })
			found := strings.Contains(out, "Duplicate password logins")
			if found != tc.wantDuplicate {
				t.Fatalf("checkUniquePasswords() found duplicate=%v; want %v; output=%q", found, tc.wantDuplicate, out)
			}
		})
	}
}

func TestHasDuplicates(t *testing.T) {
	tests := []struct {
		name      string
		input     map[string][]string
		wantHas   bool
		wantNames []string
	}{
		{
			name:    "empty map",
			input:   map[string][]string{},
			wantHas: false,
		},
		{
			name: "single entry",
			input: map[string][]string{
				"h1": {"alice"},
			},
			wantHas: false,
		},
		{
			name: "one duplicate group",
			input: map[string][]string{
				"h": {"alice", "bob"},
			},
			wantHas:   true,
			wantNames: []string{"alice", "bob"},
		},
		{
			name: "multiple groups, one duplicate",
			input: map[string][]string{
				"h1": {"alice"},
				"h2": {"bob", "carol"},
			},
			wantHas:   true,
			wantNames: []string{"bob", "carol"},
		},
	}

	containsAll := func(hay []string, needles []string) bool {
		m := make(map[string]struct{}, len(hay))
		for _, v := range hay {
			m[v] = struct{}{}
		}
		for _, n := range needles {
			if _, ok := m[n]; !ok {
				return false
			}
		}
		return true
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotNames, gotHas := hasDuplicates(tc.input)
			if gotHas != tc.wantHas {
				t.Fatalf("hasDuplicates(...) = (_, %v); want %v", gotHas, tc.wantHas)
			}
			if tc.wantHas {
				if len(gotNames) == 0 {
					t.Fatalf("hasDuplicates returned has=true but names empty; input=%v", tc.input)
				}
				if !containsAll(gotNames, tc.wantNames) {
					t.Fatalf("hasDuplicates returned names %v; want include %v", gotNames, tc.wantNames)
				}
			}
		})
	}
}

func TestPostprocessedPasswords(t *testing.T) {
	alice_lines := strings.Split("secret\n\notpauth://totp/REAL?secret=ABC", "\n")
	var alice_processed Entry
	var alice_expected Entry
	alice_expected.LoginURI = "example.com"
	alice_expected.LoginUserName = "alice@example.com"
	alice_expected.LoginPassword = "secret"
	alice_expected.SHA1 = "e5e9fa1ba31ecd1ae84f75caaa474f3a663f05f4"
	alice_expected.LoginTOT = "otpauth://totp/REAL?secret=ABC"
	alice_expected.TOTPSHA1 = "72457c98abae7ba498af5c3425619632471564a4"
	gotLines := GeneratePasswordFromLines(alice_lines, &alice_processed, alice_expected.LoginURI, alice_expected.LoginUserName)

	if gotLines != 3 {
		t.Fatalf("Got %d lines, expected %d", gotLines, 3)
	}

	if alice_processed.SHA1 != alice_expected.SHA1 {
		t.Fatalf("Bad SHA1: %s (from [%s]), expected %s (from [%s])", alice_processed.SHA1, alice_processed.LoginPassword, alice_expected.SHA1, alice_expected.LoginPassword)
	}

	if alice_processed.TOTPSHA1 != alice_expected.TOTPSHA1 {
		t.Fatalf("Bad TOTPSHA1 for %s: got %s (from [%s]), expected %s (from [%s])", alice_processed, alice_processed.TOTPSHA1, alice_processed.LoginTOT, alice_expected.TOTPSHA1, alice_expected.LoginTOT)
	}

	bob_lines := strings.Split("secret\n\notpauth://totp/FAKE?secret=ABC", "\n")
	var bob_processed Entry
	var bob_expected Entry
	bob_expected.LoginURI = "example.com"
	bob_expected.LoginUserName = "bob@example.com"
	bob_expected.LoginPassword = "secret"
	bob_expected.SHA1 = "e5e9fa1ba31ecd1ae84f75caaa474f3a663f05f4"
	bob_expected.LoginTOT = "otpauth://totp/FAKE?secret=ABC"
	bob_expected.TOTPSHA1 = "15fa60a1edc40ec35cce13e94d15d0225066dd37"
	gotLines = GeneratePasswordFromLines(bob_lines, &bob_processed, bob_expected.LoginURI, bob_expected.LoginUserName)

	if gotLines != 3 {
		t.Fatalf("Got %d lines, expected %d", gotLines, 3)
	}

	if bob_processed.SHA1 != bob_expected.SHA1 {
		t.Fatalf("Bad SHA1: %s (from [%s]), expected %s (from [%s])", bob_processed.SHA1, bob_processed.LoginPassword, bob_expected.SHA1, bob_expected.LoginPassword)
	}

	if bob_processed.TOTPSHA1 != bob_expected.TOTPSHA1 {
		t.Fatalf("Bad TOTPSHA1 for %s: got %s (from [%s]), expected %s (from [%s])", bob_processed, bob_processed.TOTPSHA1, bob_processed.LoginTOT, bob_expected.TOTPSHA1, bob_expected.LoginTOT)
	}

	carol_lines := strings.Split("\n\notpauth://totp/REAL?secret=ABC", "\n")
	var carol_processed Entry
	var carol_expected Entry
	carol_expected.LoginURI = "example.com"
	carol_expected.LoginUserName = "carol@example.com"
	carol_expected.LoginPassword = "secret"
	carol_expected.SHA1 = ""
	carol_expected.LoginTOT = "otpauth://totp/REAL?secret=ABC"
	carol_expected.TOTPSHA1 = "72457c98abae7ba498af5c3425619632471564a4"
	gotLines = GeneratePasswordFromLines(carol_lines, &carol_processed, carol_expected.LoginURI, carol_expected.LoginUserName)

	if gotLines != 3 {
		t.Fatalf("Got %d lines, expected %d", gotLines, 3)
	}

	if carol_processed.SHA1 != carol_expected.SHA1 {
		t.Fatalf("Bad SHA1: %s (from [%s]), expected %s (from [%s])", carol_processed.SHA1, carol_processed.LoginPassword, carol_expected.SHA1, carol_expected.LoginPassword)
	}

	if carol_processed.TOTPSHA1 != carol_expected.TOTPSHA1 {
		t.Fatalf("Bad TOTPSHA1 for %s: got %s (from [%s]), expected %s (from [%s])", carol_processed, carol_processed.TOTPSHA1, carol_processed.LoginTOT, carol_expected.TOTPSHA1, carol_expected.LoginTOT)
	}

	passwords := []Entry{
		alice_processed,
		bob_processed,
		carol_processed,
	}

	t.Run("Bob and Alice have the same password but not Carol", func(t *testing.T) {
		out := captureOutput(func() { CheckUniquePasswords(&passwords) })
		found := (strings.Contains(out, "bob") && strings.Contains(out, "alice") && !strings.Contains(out, "carol"))
		if !found {
			t.Fatalf("checkUniquePasswords() found duplicate=%v; want %v; output=%q", found, true, out)
		}
	})

	t.Run("Carol and Alice share the same OTP but not with Bob", func(t *testing.T) {
		out := captureOutput(func() { CheckUniqueOTP(&passwords) })
		found := (!strings.Contains(out, "bob") && strings.Contains(out, "alice") && strings.Contains(out, "carol"))
		if !found {
			t.Fatalf("checkUniquePasswords() found duplicate=%v; want %v; output=%q", found, true, out)
		}
	})

}
