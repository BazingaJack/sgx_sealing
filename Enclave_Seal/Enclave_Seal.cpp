#include "sgx_trts.h"
#include "sgx_tseal.h"
#include "stdio.h"
#include "string.h"
#include "stdlib.h"
#include "stdarg.h"

#include "sgx_tgmp.h"

#include "sgx_error.h"
#include "sgx_report.h"
#include "sgx_utils.h"

#include "Enclave_Seal_t.h"
#include "Enclave_Seal.h"

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
                                       unsigned char* p_d,
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
    memcpy(p_d, d, RSA3072_KEY_SIZE);
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

sgx_status_t sign_data_with_rsa(unsigned char* p_n,
                                unsigned char* p_d,
                                uint8_t* data, size_t data_len,
                                uint8_t* signature)
{
    sgx_status_t ret = SGX_SUCCESS;
    sgx_rsa3072_key_t prikey = {0};
    unsigned char e[EXP_SIZE] = {0X01, 0X00, 0X01, 0X00};
    
    memcpy(prikey.mod, p_n, MOD_SIZE);
    memcpy(prikey.d, p_d, MOD_SIZE);
    memcpy(prikey.e, e, EXP_SIZE);

    if (ret != SGX_SUCCESS) {
        return ret;
    }

    sgx_rsa3072_signature_t signature_data = {0};

    ret = sgx_rsa3072_sign(data, (uint32_t)data_len, &prikey, &signature_data);

    memcpy(signature, signature_data, RSA3072_KEY_SIZE);

    return ret;
}

sgx_status_t verify_signature_with_rsa(unsigned char* p_n,
                                       uint8_t* data, size_t data_len,
                                       uint8_t* signature,
                                       uint8_t* is_valid)
{
    sgx_status_t ret = SGX_SUCCESS;
    unsigned char e[EXP_SIZE] = {0X01, 0X00, 0X01, 0X00};
    
    sgx_rsa3072_public_key_t pubkey = {0};
    memcpy(pubkey.mod, p_n, MOD_SIZE);
    memcpy(pubkey.exp, e, EXP_SIZE);

    if (ret != SGX_SUCCESS) {
        return ret;
    }

    sgx_rsa3072_signature_t signature_data = {0};

    memcpy(signature_data, signature, RSA3072_KEY_SIZE);

    sgx_rsa_result_t ret_verify;
    ret = sgx_rsa3072_verify(data, (uint32_t)data_len, &pubkey, &signature_data, &ret_verify);

    if (ret != SGX_SUCCESS || ret_verify != SGX_RSA_VALID) {
        *is_valid = 0;
        return SGX_ERROR_UNEXPECTED;
    }

    *is_valid = 1;

    return ret;
}

void forge(uint8_t* s, uint8_t* q, uint8_t* t, uint8_t* r, uint8_t* t_new, uint8_t* r_new)
{
    mpz_t s_mpz, q_mpz, t_mpz, r_mpz, t_new_mpz, r_new_mpz;
    mpz_inits(s_mpz, q_mpz, t_mpz, r_mpz, t_new_mpz, r_new_mpz, NULL);
    mpz_import(s_mpz, 32, 1, 1, 0, 0, s);
    mpz_import(q_mpz, 32, 1, 1, 0, 0, q);
    mpz_import(t_mpz, 32, 1, 1, 0, 0, t);
    mpz_import(r_mpz, 32, 1, 1, 0, 0, r);
    mpz_import(t_new_mpz, 32, 1, 1, 0, 0, t_new);
    
    mpz_t r_new1, r_new2;
    mpz_inits(r_new1, r_new2, NULL);
    mpz_mul(r_new1, s_mpz, r_mpz);
    mpz_add(r_new1, r_new1, t_mpz);
    mpz_sub(r_new1, r_new1, t_new_mpz);
    if (!mpz_invert(r_new2, s_mpz, q_mpz)) {
        ocall_print_string("Error: s is not invertible mod q!\n");
        goto cleanup;
    }
    mpz_mul(r_new_mpz, r_new1, r_new2);
    mpz_mod(r_new_mpz, r_new_mpz, q_mpz);
    
    size_t written;
    mpz_export(r_new, &written, 1, 1, 0, 0, r_new_mpz);
    if (written != 32) {
        ocall_print_string("Error: r_new size is not 32 bytes!\n");
        goto cleanup;
    }
cleanup:
    mpz_clears(s_mpz, q_mpz, t_mpz, r_mpz, t_new_mpz, r_new_mpz, r_new1, r_new2, NULL);
    return;
}

uint32_t enclave_create_report(const sgx_target_info_t* p_qe3_target, sgx_report_t* p_report)
{
    sgx_report_data_t report_data = { 0 };

    // Generate the report for the app_enclave
    sgx_status_t  sgx_error = sgx_create_report(p_qe3_target, &report_data, p_report);

    return sgx_error;
}

sgx_status_t ecall_get_target_info(sgx_target_info_t* target_info) {
    return sgx_self_target(target_info);
}