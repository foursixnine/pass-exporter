package main

import (
	"bytes"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"

	"golang.org/x/term"

	"github.com/ProtonMail/gopenpgp/v3/crypto"
	"github.com/gocarina/gocsv"
)

var passwordstore_dir string
var privateKey *crypto.Key
var ignoredDirs []string

type Password struct {
	Folder                 string `csv:"folder"`
	Favorite               string `csv:"favorite"`
	Type                   string `csv:"type"`
	Name                   string `csv:"name"`
	Notes                  string `csv:"notes"`
	Fields                 string `csv:"fields"`
	RepromptMasterPassword string `csv:"reprompt"`
	LoginURI               string `csv:"login_uri"`
	LoginUserName          string `csv:"login_username"`
	LoginPassword          string `csv:"login_password"`
	LoginTOT               string `csv:"login_totp"`
}
func main() {

	var passphrase []byte

	output_file := flag.String("output", "pass_exported_passwords.csv", "File to save the exported passwords")
	privateKeyFile := flag.String("private-key", "", "Armored private key to use (required)")
	identity_email := flag.String("identity", "santiago@zarate.co", "Email that must match the identity of the private key")
	passwordstore_dir = *flag.String("password-store", "/Users/foursixnine/.password-store/suse.com", "Location to password-store directory")
	env_passprase := os.Getenv("GPG_PASSWORD")

	if *privateKeyFile == "" {
		flag.Usage()
		os.Exit(1)
	}

	if env_passprase != "" {
		passphrase = []byte(env_passprase)
		// fmt.Printf("Using %s as passprase", env_passprase)
	} else {
		passphrase = readPassphrase()
	}

	flag.Parse()

	ignoredDirs = []string{".git", "gpg"}

	keyData, err := os.ReadFile(*privateKeyFile)
	if err != nil {
		fmt.Printf("Error reading private key file: %v\n", err)
		os.Exit(2)
	}

	privateKey, err = crypto.NewPrivateKeyFromArmored(string(keyData), passphrase)
	if err != nil {
		fmt.Printf("Error unlocking private key file: %v\n", err)
		fmt.Printf("Check that the provided password matches the provided private key (%s)\n", *privateKeyFile)
		os.Exit(2)
		return
	}

	keyRing, err := crypto.NewKeyRing(privateKey)

	for _, identity := range keyRing.GetIdentities() {

		if identity.Email == *identity_email {
			fmt.Printf("Identity found: %s (%s)\n", identity.Name, identity.Email)
		}
	}

	pgp := crypto.PGP()
	decHandle, err := pgp.Decryption().DecryptionKey(privateKey).New()
	if err != nil {
		fmt.Printf("Error obtaining decryptor handle: %v\n", err)
		return
	}

	csv_file, err := os.Create(*output_file)
	if err != nil {
		panic(err)
	}
	defer csv_file.Close()

	var passwords []*Password

	var failed_to_decrypt []string
	processed_files := 0
	for _, encrypted_file := range readDirectory(passwordstore_dir) {

		fmt.Printf("Found File: %s\n", encrypted_file)
		decrypted, err := decryptFile(encrypted_file, decHandle)

		login_from_file, login_uri_from_file := getUserNameFromFilename(encrypted_file, passwordstore_dir)

		if err != nil {
			fmt.Printf("Error decrypting %s", encrypted_file)
			failed_to_decrypt = append(failed_to_decrypt, encrypted_file)
			continue
		}

		myMessage := decrypted.Bytes()

		fmt.Printf("---BEGIN DATA for %s---\n", encrypted_file)
		fmt.Println(string(myMessage))
		fmt.Println("End of raw data, processing lines:")
		lines := bytes.Split(myMessage, []byte("\n"))

		var password Password
		var notes []string

		for idx, line := range lines {
			current_line := string(line)

			if strings.HasPrefix(current_line, "otpauth:") {
				password.LoginTOT = current_line
				continue
			}
			if idx == 0 {
				password.LoginPassword = current_line
				continue
			}

			// all the rest of the lines go into notes
			notes = append(notes, current_line)

		}

		password.Folder = "Imported"
		password.Type = "Login"
		password.Name = login_uri_from_file + " " + login_from_file
		password.LoginUserName = login_from_file
		password.LoginURI = login_uri_from_file
		password.Notes = strings.Join(notes, "\n")
		passwords = append(passwords, &password)

		fmt.Printf("login %s\n", login_from_file)
		fmt.Printf("login uri: %s\n", login_uri_from_file)
		fmt.Printf("Processed %d lines\n", len(lines))
		fmt.Printf("---END DATA for %s---\n", encrypted_file)
		fmt.Println("")
		processed_files++
	}

	if len(failed_to_decrypt) > 0 {
		fmt.Printf("Failed to decrypt %d files:\n", len(failed_to_decrypt))
		for _, failed_file := range failed_to_decrypt {
			fmt.Printf("\t%s\n", failed_file)
		}
	}

	fmt.Printf("Processed %d files, %d records inserted into csv", processed_files, len(passwords))

	if err := gocsv.MarshalFile(&passwords, csv_file); err != nil {
		panic(err)
	}

	decHandle.ClearPrivateParams()

}

func readPassphrase() (passphrase []byte) {
	fmt.Print("Enter admin password: ")
	passphrase, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		fmt.Printf("Could not read password: %v", err)
	}
	return
}

func processLine(line string, idx int) {
	fmt.Printf("\tprocessing line [%s] %d\n", line, idx)
	if strings.HasPrefix(line, "otpauth:") {
		fmt.Println("\tfound otp")
	}
}

func decryptFile(file_path string, decHandle crypto.PGPDecryption) (decrypted_file *crypto.VerifiedDataResult, err error) {
	armored, err := os.ReadFile(file_path)
	if err != nil {
		fmt.Printf("Error reading file: %v\n", err)
		return
	}

	decrypted_file, err = decHandle.Decrypt(armored, crypto.Auto)
	if err != nil {
		fmt.Printf("Error decrypting file: %v\n", err)
		return
	}
	return
}

func readDirectory(path string) (files []string) {
	entryFiles, err := os.ReadDir(path)
	if err != nil {
		log.Fatal(err)
	}

	for _, file := range entryFiles {

		if path == passwordstore_dir && string(file.Name()[0]) == "." {
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
			fmt.Println(filepath.Join(path, file.Name()))
		}
	}

	return
}

func isIgnored(fileName string) bool {
	return slices.Contains(ignoredDirs, fileName)
}
