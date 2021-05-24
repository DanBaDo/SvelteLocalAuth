# SvelteLocalAuth
This component provides a encrypted local storage and authentication for local web app.

Uses PBKDF2 to derive a secret key from the password and AES-CTR for encryption.

Random salt is created for key derivation first time password is provided. New random CTR counter is created every time secret data changes.
