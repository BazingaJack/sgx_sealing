# sgx_sealing

### Compile & Make

```bash
make clean
make
```

### Usage

```bash
./app <command> [arguments...]
./app_generate_quote
./app_verify_quote
```

### Commands

```bash
# Generate RSA key pair and seal it (optionally specify output path)
./app generate_rsa_key [output_key_factor_path]
# Encrypt data file using sealed key
./app encrypt [input_data_path] [key_factor_path] [output_encrypted_path]
# Decrypt encrypted file using sealed key
./app decrypt [input_encrypted_path] [key_factor_path] [output_decrypted_path]
# Sign input data using private key
./app sign_data [input_data_path] [key_factor_path]
# Verify signature of input data using public key
./app verify_signature [input_data_path] [key_factor_path]
# Generate key, encrypt it and generate a quote (for remote attestation)
./app generate_encrypt_and_quote [output_key_factor_path]
# Generate a standalone TEE quote report
./app generate_quote
# Forge chameleon random parameter r'
./app forge [s] [q] [t] [r] [t_new]
```

### Tests

```bash
go run ./test/*.go
```