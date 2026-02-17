package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadDirectory(t *testing.T) {
	// Create a temporary directory
	tempDir := t.TempDir()

	// Create the necessary subdirectories and files
	gitDir := filepath.Join(tempDir, ".git")
	if err := os.Mkdir(gitDir, 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Create(filepath.Join(gitDir, "file")); err != nil {
		t.Fatal(err)
	}

	// Create the necessary subdirectories and files
	foobar := filepath.Join(tempDir, "foobar")
	if err := os.Mkdir(foobar, 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Create(filepath.Join(foobar, "file")); err != nil {
		t.Fatal(err)
	}

	fooDir := filepath.Join(tempDir, ".foo")
	if err := os.Mkdir(fooDir, 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Create(filepath.Join(fooDir, "file")); err != nil {
		t.Fatal(err)
	}

	if _, err := os.Create(filepath.Join(tempDir, ".anotherfile")); err != nil {
		t.Fatal(err)
	}

	if _, err := os.Create(filepath.Join(tempDir, "find_me")); err != nil {
		t.Fatal(err)
	}

	// Call the function to test
	files := readDirectory(tempDir)

	// Check expected files
	if len(files) != 2 {
		t.Errorf("Expected 2 files, got %d: %v", len(files), files)
	}

	// Check if the files are the expected ones
	expectedFiles := []string{
		filepath.Join(tempDir, "foobar", "file"),
		filepath.Join(tempDir, "find_me"),
	}
	for _, expected := range expectedFiles {
		found := false
		for _, file := range files {
			if file == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected file not found: %s", expected)
		}
	}
}
