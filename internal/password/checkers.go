package password

import "log"

func CheckUniqueOTP(passwords *[]Entry) {
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

func CheckUniquePasswords(passwords *[]Entry) {
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
