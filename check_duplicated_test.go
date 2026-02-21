package main

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
		pwds          []Password
		wantDuplicate bool
	}{
		{
			name: "no duplicates",
			pwds: []Password{
				{Name: "a", LoginTOT: "otp1", TOTPSHA1: "h1"},
				{Name: "b", LoginTOT: "otp2", TOTPSHA1: "h2"},
			},
			wantDuplicate: false,
		},
		{
			name: "duplicate otp",
			pwds: []Password{
				{Name: "a", LoginTOT: "otp1", TOTPSHA1: "h"},
				{Name: "b", LoginTOT: "otp1", TOTPSHA1: "h"},
			},
			wantDuplicate: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			out := captureOutput(func() { checkUniqueOTP(&tc.pwds) })
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
		pwds          []Password
		wantDuplicate bool
	}{
		{
			name: "no duplicates",
			pwds: []Password{
				{Name: "a", LoginPassword: "p1", SHA1: "s1"},
				{Name: "b", LoginPassword: "p2", SHA1: "s2"},
			},
			wantDuplicate: false,
		},
		{
			name: "duplicate password",
			pwds: []Password{
				{Name: "a", LoginPassword: "p", SHA1: "s"},
				{Name: "b", LoginPassword: "p", SHA1: "s"},
			},
			wantDuplicate: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			out := captureOutput(func() { checkUniquePasswords(&tc.pwds) })
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
