package password

import (
	"strings"

	"github.com/foursixnine/pass-exporter/internal/utils"
)

type Entry struct {
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

func GeneratePasswordFromLines(plaintext_lines []string, password *Entry, login_uri_from_file string, login_from_file string) (total_lines int) {
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
		password.SHA1 = utils.HashSHA1(password.LoginPassword)
	}

	if password.LoginTOT != "" {
		password.TOTPSHA1 = utils.HashSHA1(password.LoginTOT)
	}

	return // return how many lines this file had (in case somebody finds that useful)
}
