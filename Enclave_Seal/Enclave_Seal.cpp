#include "Enclave_Seal_t.h"
#include "Enclave_Seal.h"

#include "sgx_trts.h"
#include "sgx_tseal.h"
#include "stdio.h"
#include "string.h"
#include "stdlib.h"

#define RSA3072_KEY_SIZE 384
#define RSA3072_PUB_EXP_SIZE 4

uint8_t g_aes_key[AES_GCM_KEY_SIZE] = {0};

uint32_t get_sealed_data_size(size_t *aad_mac_text_len, size_t *encrypt_data_len)
{
    return sgx_calc_sealed_data_size((uint32_t)(*aad_mac_text_len), (uint32_t)(*encrypt_data_len));
}

sgx_status_t seal_data(uint8_t* p_aad_mac_text, size_t add_mac_text_len, uint8_t* p_encrypt_data, size_t encrypt_data_len,uint8_t* sealed_blob, uint32_t data_size)
{
    uint32_t sealed_data_size = sgx_calc_sealed_data_size((uint32_t)add_mac_text_len, (uint32_t)encrypt_data_len);
    if (sealed_data_size == UINT32_MAX)
        return SGX_ERROR_UNEXPECTED;
    if (sealed_data_size > data_size)
        return SGX_ERROR_INVALID_PARAMETER;

    uint8_t *temp_sealed_buf = (uint8_t *)malloc(sealed_data_size);
    if(temp_sealed_buf == NULL)
        return SGX_ERROR_OUT_OF_MEMORY;
    sgx_status_t  err = sgx_seal_data((uint32_t)add_mac_text_len, (const uint8_t *)p_aad_mac_text, (uint32_t)encrypt_data_len, p_encrypt_data, sealed_data_size, (sgx_sealed_data_t *)temp_sealed_buf);
    if (err == SGX_SUCCESS)
    {
        // Copy the sealed data to outside buffer
        memcpy(sealed_blob, temp_sealed_buf, sealed_data_size);
    }

    free(temp_sealed_buf);
    return err;
}

sgx_status_t generate_aes_key_and_seal(uint8_t* sealed_key, uint32_t sealed_key_size)
{
    sgx_status_t ret = sgx_read_rand(g_aes_key, AES_GCM_KEY_SIZE);
    ret = seal_data(NULL, 0, g_aes_key, AES_GCM_KEY_SIZE, sealed_key, sealed_key_size);
    return ret;
}

sgx_status_t generate_rsa_key_and_seal(unsigned char* p_n,
                                       unsigned char* p_p,
                                       unsigned char* p_q,
                                       unsigned char* p_dmp1,
                                       unsigned char* p_dmq1,
                                       unsigned char* p_iqmp)
{
    sgx_status_t ret = SGX_SUCCESS;
    unsigned char n[RSA3072_KEY_SIZE] = {0};
    unsigned char d[RSA3072_KEY_SIZE] = {0};
    unsigned char e[RSA3072_PUB_EXP_SIZE] = {0X01, 0X00, 0X01, 0X00};
    unsigned char p[RSA3072_KEY_SIZE/2] = {0};
    unsigned char q[RSA3072_KEY_SIZE/2] = {0};
    unsigned char dmp1[RSA3072_KEY_SIZE/2] = {0};
    unsigned char dmq1[RSA3072_KEY_SIZE/2] = {0};
    unsigned char iqmp[RSA3072_KEY_SIZE/2] = {0};

    ret = sgx_create_rsa_key_pair(RSA3072_KEY_SIZE, RSA3072_PUB_EXP_SIZE, n, d, e, p, q, dmp1, dmq1, iqmp);
    if (ret != SGX_SUCCESS) {
        return ret;
    }

    memcpy(p_n, n, RSA3072_KEY_SIZE);
    memcpy(p_p, p, RSA3072_KEY_SIZE/2);
    memcpy(p_q, q, RSA3072_KEY_SIZE/2);
    memcpy(p_dmp1, dmp1, RSA3072_KEY_SIZE/2);
    memcpy(p_dmq1, dmq1, RSA3072_KEY_SIZE/2);
    memcpy(p_iqmp, iqmp, RSA3072_KEY_SIZE/2);

    return ret;
}

sgx_status_t encrypt_by_rsa_pubkey(unsigned char* p_n, unsigned char* plain_text, size_t plain_text_len, unsigned char* cipher_text, size_t cipher_text_len)
{
    void* pub_key;
    unsigned char e[EXP_SIZE] = {0X01, 0X00, 0X01, 0X00};
    sgx_status_t ret = sgx_create_rsa_pub1_key(MOD_SIZE, EXP_SIZE, p_n, e, &pub_key);

    ret = sgx_rsa_pub_encrypt_sha256(pub_key, cipher_text, &cipher_text_len, (const unsigned char*)plain_text, plain_text_len);

    return ret;
}

void get_unsealed_data_size(const uint8_t *sealed_blob, size_t data_size, uint32_t *p_mac_text_len, uint32_t *p_decrypt_data_len)
{
    uint32_t mac_text_len = sgx_get_add_mac_txt_len((const sgx_sealed_data_t *)sealed_blob);
    uint32_t decrypt_data_len = sgx_get_encrypt_txt_len((const sgx_sealed_data_t *)sealed_blob);
    *p_mac_text_len = mac_text_len;
    *p_decrypt_data_len = decrypt_data_len;
}

sgx_status_t unseal_data(const uint8_t *sealed_blob, size_t data_size, uint8_t *p_mac_text, size_t mac_data_size, uint8_t *p_decrypt_data, size_t decrypt_data_size)
{
    uint32_t mac_text_len = sgx_get_add_mac_txt_len((const sgx_sealed_data_t *)sealed_blob);
    uint32_t decrypt_data_len = sgx_get_encrypt_txt_len((const sgx_sealed_data_t *)sealed_blob);
    // ocall_print_num(&mac_text_len);
    // ocall_print_num(&decrypt_data_len);
    if (mac_text_len == UINT32_MAX || decrypt_data_len == UINT32_MAX)
        return SGX_ERROR_UNEXPECTED;
    if(mac_text_len > data_size || decrypt_data_len > data_size)
        return SGX_ERROR_INVALID_PARAMETER;

    uint8_t *de_mac_text =(uint8_t *)malloc(mac_text_len);
    if(de_mac_text == NULL)
        return SGX_ERROR_OUT_OF_MEMORY;
    uint8_t *decrypt_data = (uint8_t *)malloc(decrypt_data_len);
    if(decrypt_data == NULL)
    {
        free(de_mac_text);
        return SGX_ERROR_OUT_OF_MEMORY;
    }

    sgx_status_t ret = sgx_unseal_data((const sgx_sealed_data_t *)sealed_blob, de_mac_text, &mac_text_len, decrypt_data, &decrypt_data_len);
    if (ret != SGX_SUCCESS)
    {
        free(de_mac_text);
        free(decrypt_data);
        return ret;
    }

    memcpy(p_mac_text, de_mac_text, mac_data_size);
    memcpy(p_decrypt_data, decrypt_data, decrypt_data_size);

    free(de_mac_text);
    free(decrypt_data);
    return ret;
}

sgx_status_t decrypt_by_rsa_prikey(unsigned char* p_p,
                                   unsigned char* p_q,
                                   unsigned char* p_dmp1,
                                   unsigned char* p_dmq1,
                                   unsigned char* p_iqmp,
                                   uint8_t* cipher_text, size_t cipher_text_len,
                                   uint8_t* original_text, size_t original_text_len)
{
    sgx_status_t ret = SGX_SUCCESS;
    void* prikey;
    unsigned char e[EXP_SIZE] = {0X01, 0X00, 0X01, 0X00};
    ret = sgx_create_rsa_priv2_key(MOD_SIZE, EXP_SIZE, e, p_p, p_q, p_dmp1, p_dmq1, p_iqmp, &prikey);

    ret = sgx_rsa_priv_decrypt_sha256(prikey, original_text, &original_text_len, (const unsigned char*)cipher_text, cipher_text_len);

    return ret;
}