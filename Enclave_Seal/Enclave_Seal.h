#include <stdint.h>
#include "sgx_tseal.h"

#define AES_GCM_KEY_SIZE 16
#define EXP_SIZE 4
#define MOD_SIZE 384

uint32_t get_sealed_data_size(size_t *aad_mac_text_len, size_t *encrypt_data_len);
sgx_status_t seal_data(uint8_t* p_aad_mac_text, size_t add_mac_text_len, uint8_t* p_encrypt_data, size_t encrypt_data_len,uint8_t* sealed_blob, uint32_t data_size);
sgx_status_t generate_aes_key_and_seal(uint8_t* sealed_key, uint32_t sealed_key_size);
sgx_status_t generate_rsa_key_and_seal(unsigned char* p_n, unsigned char* p_p, unsigned char* p_q, unsigned char* p_dmp1, unsigned char* p_dmq1, unsigned char* p_iqmp);
sgx_status_t encrypt_by_rsa_pubkey(unsigned char* p_n, unsigned char* plain_text, size_t plain_text_len, unsigned char* cipher_text, size_t cipher_text_len);
void get_unsealed_data_size(const uint8_t *sealed_blob, size_t data_size, uint32_t *p_mac_text_len, uint32_t *p_decrypt_data_len);
sgx_status_t unseal_data(const uint8_t *sealed_blob, size_t data_size, uint8_t *p_mac_text, size_t mac_data_size, uint8_t *p_decrypt_data, size_t decrypt_data_size);
sgx_status_t decrypt_by_rsa_prikey(unsigned char* p_p, unsigned char* p_q, unsigned char* p_dmp1, unsigned char* p_dmq1, unsigned char* p_iqmp, uint8_t* cipher_text, size_t cipher_text_len, uint8_t* original_text, size_t original_text_len);