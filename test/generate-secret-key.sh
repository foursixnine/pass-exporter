export GNUPGHOME="$(mktemp -d -p $PWD -t GPG)"
gpg --passphrase 'secret' --batch --quick-gen-key "Pepe Perez <pperez@example.com>"
export FINGERPRINT=$(gpg --list-options show-only-fpr-mbox --list-secret-keys | awk '{print $1}')

# This is how pass encrypts:
echo passwordsupersecretpassword | gpg -e -r $FINGERPRINT -o test/example.com/mysecret.gpg --quiet --yes --compress-algo=none --no-encrypt-to
echo "run # gpg --armor  --export-secret-keys $FINGERPRINT > private-key.asc"
