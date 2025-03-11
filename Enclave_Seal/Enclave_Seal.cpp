/*
 * Copyright (C) 2011-2021 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

 #include "Enclave_Seal_t.h"
 #include "Enclave_Seal.h"
 
 #include "sgx_trts.h"
 #include "sgx_tseal.h"
 #include "stdio.h"
 #include "string.h"
 #include "stdlib.h"
 
 uint8_t g_aes_key[AES_GCM_KEY_SIZE] = {0};
 sgx_rsa3072_public_key_t *g_rsa_pub_key = (sgx_rsa3072_public_key_t *)malloc(sizeof(sgx_rsa3072_public_key_t));
 sgx_rsa3072_key_t *g_rsa_pri_key = (sgx_rsa3072_key_t *)malloc(sizeof(sgx_rsa3072_key_t));
 
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
 
 sgx_status_t generate_rsa_key_and_seal(unsigned char* p_n, uint8_t* sealed_pri_key, uint32_t sealed_pri_key_size)
 {
     //TODO store all fators on disk and load them when needed
     //TODO only n and e can be stored directly on disk while other factors should be sealed before stored
     sgx_status_t ret = SGX_SUCCESS;
     unsigned char *n = (unsigned char*)malloc(MOD_SIZE);
     unsigned char *d = (unsigned char*)malloc(MOD_SIZE);
     uint8_t e[] = {0X01, 0X00, 0X01, 0X00};
     unsigned char *p = (unsigned char*)malloc(MOD_SIZE);
     unsigned char *q = (unsigned char*)malloc(MOD_SIZE);
     unsigned char *dmp1 = (unsigned char*)malloc(MOD_SIZE);
     unsigned char *dmq1 = (unsigned char*)malloc(MOD_SIZE);
     unsigned char *iqmp = (unsigned char*)malloc(MOD_SIZE);
 
     ret = sgx_create_rsa_key_pair(MOD_SIZE, EXP_SIZE, n, d, e, p, q, dmp1, dmq1, iqmp);
     memcpy(g_rsa_pri_key->mod, n, MOD_SIZE);
     memcpy(g_rsa_pri_key->d, d, MOD_SIZE);
     memcpy(g_rsa_pri_key->e, e, EXP_SIZE);
     memcpy(g_rsa_pub_key->mod, n, MOD_SIZE);
     memcpy(g_rsa_pub_key->exp, e, EXP_SIZE);
 
     memcpy(p_n, n, MOD_SIZE);
     ret = seal_data(NULL, 0, (uint8_t *)g_rsa_pri_key, sizeof(sgx_rsa3072_key_t), sealed_pri_key, sealed_pri_key_size);
     
     // char data[12] = "hello world";
     // sgx_rsa_result_t p_result;
     // sgx_rsa3072_signature_t* p_sig = (sgx_rsa3072_signature_t*)malloc(sizeof(sgx_rsa3072_signature_t));
     // ret = sgx_rsa3072_sign((uint8_t*)&data, sizeof(char)*12, &g_rsa_pri_key, p_sig);
     // ret = sgx_rsa3072_verify((uint8_t*)&data, sizeof(char)*12, g_rsa_pub_key, p_sig, &p_result);
 
     // size_t* pout_len = (size_t*)malloc(sizeof(size_t));
 
     // void* other_rsa;
 
     // ret = sgx_create_rsa_pub1_key(MOD_SIZE, EXP_SIZE, n, e, &other_rsa);
 
     // ret = sgx_rsa_pub_encrypt_sha256(other_rsa, NULL, pout_len, (const unsigned char*)&data, sizeof(data));
     // uint8_t *out_data = (uint8_t*) malloc(*pout_len);
     // ret = sgx_rsa_pub_encrypt_sha256(other_rsa,out_data,pout_len, (const unsigned char*)&data, sizeof(data));
 
 
     // if(ret != SGX_SUCCESS)
     // {
     //     ocall_print_string("Failed to get the length of the output buffer");
     // }
 
     // uint8_t *out_data = (uint8_t*)malloc(12);
     // ret = sgx_rsa_pub_encrypt_sha256(other_rsa, out_data, pout_len, (unsigned char*)&data, sizeof(data));
 
     free(n);
     free(d);
     free(p);
     free(q);
     free(dmp1);
     free(dmq1);
     free(iqmp);
 
     return ret;
 }
 
 sgx_status_t encrypt_by_rsa_pubkey(unsigned char* p_n,uint8_t* plain_text, size_t plain_text_len, uint8_t* cipher_text, size_t* cipher_text_len)
 {
     void* pub_key;
     uint8_t e[] = {0X01, 0X00, 0X01, 0X00};
     sgx_status_t ret = sgx_create_rsa_pub1_key(MOD_SIZE, EXP_SIZE, p_n, e, &pub_key);
 
     if(*cipher_text_len == 0) {
         ret = sgx_rsa_pub_encrypt_sha256(pub_key, NULL, cipher_text_len, plain_text, plain_text_len);
     } else {
         ret = sgx_rsa_pub_encrypt_sha256(pub_key, cipher_text, cipher_text_len, plain_text, plain_text_len);
     }
 
     // ret = sgx_rsa_pub_encrypt_sha256(pub_key, NULL, cipher_text_len, plain_text, plain_text_len);
     // uint8_t *out_data = (uint8_t*)malloc(*cipher_text_len);
 
     // ret = sgx_rsa_pub_encrypt_sha256(pub_key, out_data, cipher_text_len, plain_text, plain_text_len);
     // memcpy(cipher_text, out_data, *cipher_text_len);
     return ret;
 }