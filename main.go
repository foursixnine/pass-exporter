package main

import (
	"bytes"
	"flag"
	"fmt"
	"log"
	"os"
	"path"
	"strings"
	"sync"

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

	ignoredDirs = []string{"gpg"}

	help := flag.Bool("help", false, "Show help")
	output_file := flag.String("output", "pass_exported_passwords.csv", "File to save the exported passwords")
	privateKeyFile := flag.String("private-key", "", "Armored private key to use (required)")
	identity_email := flag.String("identity", "", "Email that must match the identity of the private key (required)")
	passwordstore_dir = *flag.String("password-store", "~/.password-store", "Location to password-store directory")
	env_passprase := os.Getenv("GPG_PASSWORD")

	flag.Parse()

	if *help {
		flag.Usage()
		os.Exit(0)
	}

	if *privateKeyFile == "" || *identity_email == "" {
		flag.Usage()
		log.Fatal("A private key file and an Identity email must be provided")
	}

	if env_passprase != "" {
		passphrase = []byte(env_passprase)
		// fmt.Printf("Using %s as passprase", env_passprase)
	} else {
		passphrase = readPassphrase()
	}

	keyData, err := os.ReadFile(*privateKeyFile)
	if err != nil {
		fmt.Printf("Error reading private key file: %v\n", err)
		os.Exit(2)
	}

	privateKey, err = crypto.NewPrivateKeyFromArmored(string(keyData), passphrase)
	if err != nil {
		log.Printf("Error unlocking private key file: %v\n", err)
		log.Fatalf("Check that the provided password matches the provided private key (%s)\n", *privateKeyFile)
		os.Exit(2)
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

	var passwords []Password
	var failed_to_decrypt []string
	processed_files := 0
	var wg sync.WaitGroup
	var mutex sync.Mutex

	for _, encrypted_file := range readDirectory(passwordstore_dir) {
		fmt.Printf("Found File: %s\n", encrypted_file)
		wg.Add(1)
		go func() {
			password, err := processFile(encrypted_file, decHandle)
			if err != nil {
				fmt.Printf("Error decrypting %s", encrypted_file)
				mutex.Lock()
				failed_to_decrypt = append(failed_to_decrypt, encrypted_file)
				mutex.Unlock()
				wg.Done()
				return
			}
			mutex.Lock()
			passwords = append(passwords, password)
			processed_files++
			mutex.Unlock()
			wg.Done()
		}()
	}

	wg.Wait()

	if len(failed_to_decrypt) > 0 {
		fmt.Printf("Failed to decrypt %d files:\n", len(failed_to_decrypt))
		for _, failed_file := range failed_to_decrypt {
			fmt.Printf("\t%s\n", failed_file)
		}
	}

	csv_file, err := os.Create(*output_file)
	if err != nil {
		panic(err)
	}
	defer csv_file.Close()

	if err := gocsv.MarshalFile(&passwords, csv_file); err != nil {
		panic(err)
	}

	fmt.Printf("Processed %d files, %d records inserted into csv.\n", processed_files, len(passwords))
	decHandle.ClearPrivateParams()

}

func processFile(encrypted_file string, decHandle crypto.PGPDecryption) (password Password, err error) {
	login_from_file, login_uri_from_file := getUserNameFromFilename(encrypted_file, passwordstore_dir)

	decrypted, err := decryptFile(encrypted_file, decHandle)
	if err != nil {
		return
	}

	myMessage := decrypted.Bytes()

	fmt.Printf("---BEGIN DATA for %s---\n", encrypted_file)
	// fmt.Println(string(myMessage))
	// fmt.Println("End of raw data, processing lines:")

	var notes []string
	lines := bytes.Split(myMessage, []byte("\n"))
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

	fmt.Printf("login %s\n", login_from_file)
	fmt.Printf("login uri: %s\n", login_uri_from_file)
	fmt.Printf("Processed %d lines\n", len(lines))
	fmt.Printf("---END DATA for %s---\n", encrypted_file)
	fmt.Println("")

	return
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

// Passwords are stored in `domain/login` format
func getUserNameFromFilename(target_file string, pass_dir string) (base_name string, base_path string) {
	pass_dir = expandHomeDir(pass_dir)
	wd_file := strings.TrimPrefix(target_file, pass_dir)
	// if wd_file == target_file {
	// 	log.Fatalf("ERROR: Target file '%s' contains prefix '%s', seems unmodified", wd_file, pass_dir)
	// }
	base_name = path.Base(wd_file)
	base_name = strings.TrimSuffix(base_name, ".gpg")
	base_path = path.Dir(wd_file)

	// Remove leading slash from base_path if it exists
	base_path = strings.TrimPrefix(base_path, "/")

	return
}
