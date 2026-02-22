package main

import "testing"

func TestHashSHA1(t *testing.T) {
	got := hashSHA1("hello")
	want := "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"
	if got != want {
		t.Fatalf("hashSHA1(\"hello\") = %q; want %q", got, want)
	}
}
