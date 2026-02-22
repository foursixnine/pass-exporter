package main

import (
	"crypto/sha1"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"

	"github.com/ProtonMail/gopenpgp/v3/crypto"
	"github.com/foursixnine/pass-exporter/internal/utils"
	"github.com/gocarina/gocsv"
)

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
	SHA1                   string `csv:"-"`
	TOTPSHA1               string `csv:"-"`
}

type Options struct {
	OutputFile       string
	PrivateKeyFile   string
	IdentityEmail    string
	PasswordStoreDir string
	IgnoredDirs      utils.IgnoreDirs
}

var Config Options

func main() {

	var passphrase []byte
	var private_key *crypto.Key

	help := flag.Bool("help", false, "Show help")
	flag.StringVar(&Config.OutputFile, "output", "pass_exported_passwords.csv", "File to save the exported passwords")
	flag.StringVar(&Config.PrivateKeyFile, "private-key", "", "Armored private key to use (required)")
	flag.StringVar(&Config.IdentityEmail, "identity", "", "Email that must match the identity of the private key (required)")
	flag.StringVar(&Config.PasswordStoreDir, "password-store", "", "Location to password-store directory")
	flag.Var(&Config.IgnoredDirs, "ignore-dir", "Ignore directory, can be used multiple times")
	env_passprase := os.Getenv("GPG_PASSWORD")

	flag.Parse()

	if *help {
		flag.Usage()
		os.Exit(0)
	}

	if Config.PrivateKeyFile == "" || Config.IdentityEmail == "" {
		flag.Usage()
		log.Fatal("A private key file and an Identity email must be provided")
	}

	if env_passprase != "" {
		passphrase = []byte(env_passprase)
		// log.Printf("Using %s as passprase", env_passprase)
	} else {
		passphrase = utils.ReadPassphrase()
	}

	key_data, err := os.ReadFile(Config.PrivateKeyFile)
	if err != nil {
		log.Fatalf("Error reading private key file: %v\n", err)
	}

	private_key, err = crypto.NewPrivateKeyFromArmored(string(key_data), passphrase)
	if err != nil {
		log.Printf("Error unlocking private key file: %v\n", err)
		log.Fatalf("Check that the provided password matches the provided private key (%s)\n", Config.PrivateKeyFile)
	}

	keyRing, err := crypto.NewKeyRing(private_key)

	for _, identity := range keyRing.GetIdentities() {
		if identity.Email == Config.IdentityEmail {
			log.Printf("Identity found: %s (%s)\n", identity.Name, identity.Email)
		}
	}

	pgp := crypto.PGP()
	decryption_handle, err := pgp.Decryption().DecryptionKey(private_key).New()
	if err != nil {
		log.Fatalf("Error obtaining decryptor handle: %v\n", err)
		return
	}

	var passwords []Password
	var failed_to_decrypt []string
	processed_files := 0
	var wg sync.WaitGroup
	var mutex sync.Mutex

	for _, encrypted_file := range utils.ReadDirectory(Config.IgnoredDirs, Config.PasswordStoreDir) {
		if !strings.HasSuffix(encrypted_file, ".gpg") {
			// log.Printf("Ignoring file %s\n", encrypted_file)
			continue
		}
		log.Printf("Found file: %s\n", encrypted_file)
		wg.Add(1)
		go func() {
			password, err := processEncryptedFile(encrypted_file, decryption_handle)
			if err != nil {
				log.Printf("Error processing file %s\n", encrypted_file)
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
		log.Printf("Failed to decrypt %d files:\n", len(failed_to_decrypt))
		for _, failed_file := range failed_to_decrypt {
			log.Printf("\t%s\n", failed_file)
		}
	}

	checkUniqueOTP(&passwords)
	checkUniquePasswords(&passwords)

	csv_file, err := os.Create(Config.OutputFile)
	if err != nil {
		log.Fatalln(err)
	}
	defer csv_file.Close()

	if err := gocsv.MarshalFile(&passwords, csv_file); err != nil {
		log.Fatalln(err)
	}

	log.Printf("Processed %d files, %d records inserted into csv.\n", processed_files, len(passwords))
	decryption_handle.ClearPrivateParams()

}

func hashSHA1(s string) string {

	return fmt.Sprintf("%x", sha1.Sum([]byte(s)))

}

func checkUniqueOTP(passwords *[]Password) {
	seenOTPs := make(map[string][]string)
	log.Println("Checking for duplicate otp tokens")
	for _, password := range *passwords {
		if password.LoginTOT == "" {
			continue
		}
		seenOTPs[password.TOTPSHA1] = append(seenOTPs[password.TOTPSHA1], password.Name)
		// log.Printf("%x", password.TOTPSHA1)
	}

	usernames, has_duplicates := hasDuplicates(seenOTPs)
	if has_duplicates {
		log.Printf("Duplicate OTP found for users: %v with OTP\n", usernames)
	}
}

func checkUniquePasswords(passwords *[]Password) {
	seenPasswords := make(map[string][]string)

	for _, password := range *passwords {
		if password.LoginPassword == "" {
			continue
		}
		seenPasswords[password.SHA1] = append(seenPasswords[password.SHA1], password.Name)
	}

	usernames, has_duplicates := hasDuplicates(seenPasswords)
	if has_duplicates {
		log.Printf("Duplicate password logins: %v\n", usernames)
	}
}

func hasDuplicates(seen_usernames map[string][]string) (usernames []string, has_duplicates bool) {
	for _, group := range seen_usernames {
		if len(group) > 1 {
			has_duplicates = true
			usernames = append(usernames, group...)
		}
	}
	return
}

func processEncryptedFile(encrypted_file string, decHandle crypto.PGPDecryption) (password Password, err error) {
	login_from_file, login_uri_from_file := utils.GetUserNameFromFilename(encrypted_file, Config.PasswordStoreDir)

	decrypted, err := decryptFile(encrypted_file, decHandle)
	if err != nil {
		return
	}

	decrypted_bytes := decrypted.Bytes()

	log.Printf("---BEGIN DATA for %s---\n", encrypted_file)
	lines := strings.Split(string(decrypted_bytes), "\n") //bytes.Split(decrypted_bytes, []byte("\n"))
	total_lines := generatePasswordFromLines(lines, &password, login_uri_from_file, login_from_file)

	log.Printf("login %s\n", login_from_file)
	log.Printf("login uri: %s\n", login_uri_from_file)
	log.Printf("Processed %d lines\n", total_lines)
	log.Printf("---END DATA for %s---\n", encrypted_file)
	fmt.Println("")

	return
}

func generatePasswordFromLines(plaintext_lines []string, password *Password, login_uri_from_file string, login_from_file string) (total_lines int) {
	var notes []string

	for idx, current_line := range plaintext_lines {
		total_lines++

		if strings.HasPrefix(current_line, "otpauth:") {
			password.LoginTOT = current_line
			continue
		}

		if idx == 0 && current_line != "" {
			password.LoginPassword = current_line
			continue
		}

		notes = append(notes, current_line)

	}

	password.Folder = "Imported"
	password.Type = "Login"
	password.Name = login_uri_from_file + " " + login_from_file
	password.LoginUserName = login_from_file
	password.LoginURI = login_uri_from_file
	password.Notes = strings.Join(notes, "\n")

	if password.LoginPassword != "" {
		password.SHA1 = hashSHA1(password.LoginPassword)
	}

	if password.LoginTOT != "" {
		password.TOTPSHA1 = hashSHA1(password.LoginTOT)
	}

	return // return how many lines this file had (in case somebody finds that useful)
}

func decryptFile(file_path string, decHandle crypto.PGPDecryption) (decrypted_file *crypto.VerifiedDataResult, err error) {
	armored, err := os.ReadFile(file_path)
	if err != nil {
		log.Printf("Error reading file: %v\n", err)
		return
	}

	decrypted_file, err = decHandle.Decrypt(armored, crypto.Auto)
	if err != nil {
		log.Printf("Error decrypting file: %v\n", err)
		return
	}
	return
}
