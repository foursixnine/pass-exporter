package utils

import (
	"crypto/sha1"
	"fmt"
	"log"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"syscall"

	"golang.org/x/term"
)

type IgnoreDirs []string

// String is an implementation of the flag.Value interface
func (i *IgnoreDirs) String() string {
	return fmt.Sprintf("%v", *i)
}

// Set is an implementation of the flag.Value interface
func (i *IgnoreDirs) Set(value string) error {
	*i = append(*i, value)
	return nil
}

func ExpandHomeDir(src_path string) (path string) {
	path = src_path
	if strings.HasPrefix(path, "~") {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			log.Fatal("Error trying to detect the user's home directory")
			os.Exit(2)
		}

		path = filepath.Join(homeDir, path[1:])
	}
	return
}

func ReadDirectory(ignoredDirs []string, path string) (files []string) {

	path = ExpandHomeDir(path)

	entryFiles, err := os.ReadDir(path)
	if err != nil {
		log.Fatalf("Error reading directory (%s), %s", path, err)
	}

	for _, file := range entryFiles {

		if strings.HasPrefix(file.Name(), ".") {
			continue
		}

		if file.IsDir() {
			if IsIgnored(ignoredDirs, file.Name()) {
				continue
			}
			directoryFiles := ReadDirectory(ignoredDirs, filepath.Join(path, file.Name()))
			files = append(files, directoryFiles...)
		} else {
			path_to_file := filepath.Join(path, file.Name())
			files = append(files, path_to_file)
			// fmt.Println(filepath.Join(path, file.Name()))
		}
	}

	return
}

func IsIgnored(ignoredDirs []string, fileName string) bool {
	return slices.Contains(ignoredDirs, fileName)
}

func ReadPassphrase() (passphrase []byte) {
	fmt.Print("Enter admin password: ")
	passphrase, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		fmt.Printf("Could not read password: %v", err)
	}
	fmt.Println()
	return
}

// Passwords are stored in `domain/login` format
func GetUserNameFromFilename(target_file string, pass_dir string) (base_name string, base_path string) {
	pass_dir = ExpandHomeDir(pass_dir)
	wd_file := strings.TrimPrefix(target_file, pass_dir)

	base_name = path.Base(wd_file)
	base_name = strings.TrimSuffix(base_name, ".gpg")
	base_path = path.Dir(wd_file)

	// Remove leading slash from base_path if it exists
	base_path = strings.TrimPrefix(base_path, "/")

	return
}

func HashSHA1(s string) string {

	return fmt.Sprintf("%x", sha1.Sum([]byte(s)))

}
