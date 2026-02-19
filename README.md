# pass-exporter

This is a rudimentary attempt (that surprisingly works) to export passwords from [pass](https://www.passwordstore.org) to Bitwarden  [csv format](https://bitwarden.com/help/condition-bitwarden-import/)

As a requisite you need to have the private key that protects the passwords, exported as an ASCII armored key (Or whatever the nomenclature is), the important bit is that you export it:

`gpg --export-secret-keys --armor $YOURFINGERPRINT > private-key.asc`

To run simply run directly

```
go run . --private-key private_key.asc --identity alice@example.com
```

Alternatively you can build it and then run it (Sky is the limit)

As usual PRs are welcome, specially for adding tests
