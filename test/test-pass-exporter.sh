set -x
EXPORT_FILE="pass_exported_passwords.csv"
rm ${EXPORT_FILE} || true
go run cmd/main.go --private-key test/private-key.asc --identity pperez@example.com --ignore-dir git --ignore-dir gpg --password-store test/data
if ! grep -q secret "${EXPORT_FILE}"; then
  echo "Test failed"
fi
