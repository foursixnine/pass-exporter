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

func TestGetUserNameFromFilename(t *testing.T) {
	tests := []struct {
		name         string
		targetFile   string
		passDir      string
		expectedBase string
		expectedPath string
	}{
		{
			name:         "Basic Test, domain/login",
			targetFile:   "/path/to/something/here/i/care/about.com.gpg",
			passDir:      "/path/to/something",
			expectedBase: "about.com",
			expectedPath: "here/i/care",
		},
		{
			name:         "No Modification",
			targetFile:   "/another/path/to/file.txt",
			passDir:      "/different/path",
			expectedBase: "file.txt",
			expectedPath: "another/path/to",
		},
		{
			name:         "Empty Path",
			targetFile:   "/path/to/file.txt",
			passDir:      "/path/to",
			expectedBase: "file.txt",
			expectedPath: "",
		},
		// {
		// 	name:         "Only Base Name",
		// 	targetFile:   "/path/to/file/",
		// 	passDir:      "/path/to/file",
		// 	expectedBase: "file",
		// 	expectedPath: "",
		// },
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			baseName, basePath := getUserNameFromFilename(tt.targetFile, tt.passDir)

			if baseName != tt.expectedBase {
				t.Errorf("expected %s, got %s", tt.expectedBase, baseName)
			}
			if basePath != tt.expectedPath {
				t.Errorf("expected %s, got %s", tt.expectedPath, basePath)
			}
		})
	}
}
