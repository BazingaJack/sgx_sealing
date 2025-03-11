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

 #include "Enclave_Unseal_t.h"

 #include "sgx_trts.h"
 #include "sgx_tseal.h"
 #include "stdio.h"
 #include "string.h"
 #include "stdlib.h"
 
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
                                    uint8_t* original_text, size_t* original_text_len)
 {
     sgx_status_t ret = SGX_SUCCESS;
     //TODO decrypt the cipher_text by RSA private key
     //TODO use sgx_create_rsa_priv2_key to recreate prikey because it is more fast and consumes less resources
     
     return ret;
 }