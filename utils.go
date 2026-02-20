package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"

	"golang.org/x/term"
)

type ignoreDirs []string

// String is an implementation of the flag.Value interface
func (i *ignoreDirs) String() string {
	return fmt.Sprintf("%v", *i)
}

// Set is an implementation of the flag.Value interface
func (i *ignoreDirs) Set(value string) error {
	*i = append(*i, value)
	return nil
}

func expandHomeDir(src_path string) (path string) {
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

func readDirectory(path string) (files []string) {

	path = expandHomeDir(path)

	entryFiles, err := os.ReadDir(path)
	if err != nil {
		log.Fatalf("Error reading directory (%s), %s", path, err)
	}

	for _, file := range entryFiles {

		if strings.HasPrefix(file.Name(), ".") {
			continue
		}

		if file.IsDir() {
			if isIgnored(file.Name()) {
				continue
			}
			directoryFiles := readDirectory(filepath.Join(path, file.Name()))
			files = append(files, directoryFiles...)
		} else {
			path_to_file := filepath.Join(path, file.Name())
			files = append(files, path_to_file)
			// fmt.Println(filepath.Join(path, file.Name()))
		}
	}

	return
}

func isIgnored(fileName string) bool {
	return slices.Contains(Config.IgnoredDirs, fileName)
}

func readPassphrase() (passphrase []byte) {
	fmt.Print("Enter admin password: ")
	passphrase, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		fmt.Printf("Could not read password: %v", err)
	}
	fmt.Println()
	return
}
