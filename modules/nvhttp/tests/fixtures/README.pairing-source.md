These deliberately public test-only RSA identities were generated independently
with the system OpenSSL CLI, using `req -x509 -newkey rsa:2048 -sha256 -nodes`,
CNs `Amaterasu-Pairing-Test-Client` and `Amaterasu-Pairing-Test-Host`, and 3650-day
validity. Never deploy these private keys.

The fixed client-challenge vector uses salt bytes 00 through 0f, ASCII PIN 1234,
and 16 plaintext bytes 11. Python hashlib independently gives AES key
`bad0b4f7cae08eb7c1b5acc763a8ed25`; OpenSSL `enc -aes-128-ecb -nopad -K <key>`
gives ciphertext `aad45a6506af0973b77bcc7262fe36d5`.
