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

// App.cpp : Define the entry point for the console application.
//

#include <string.h>
#include <assert.h>
#include <fstream>
#include <thread>
#include <iostream>

#include "sgx_urts.h"
#include "Enclave_Seal_u.h"
#include "Enclave_Unseal_u.h"

#include "ErrorSupport.h"

#include "sgx_tcrypto.h"

#define ENCLAVE_NAME_SEAL "libenclave_seal.signed.so"
#define ENCLAVE_NAME_UNSEAL "libenclave_unseal.signed.so"
#define ORIGIN_MAC_TEXT "origin_mac_text.txt"
#define ORIGIN_DATA "origin_data.txt"
#define SEALED_DATA_FILE "sealed_data_blob.txt"
#define UNSEALED_MAC_TEXT "unsealed_mac_text.txt"
#define UNSEALED_DECRYPT_DATA "unsealed_decrypt_data.txt"
#define SEALED_KEY_FILE "sealed_key.txt"
#define SEALED_RSA_PRI_KEY_FILE "sealed_rsa_pri_key.txt"
#define RSA_FACTOR_N_FILE "rsa_factor_n.txt"
#define RSA_ENCRYPTED_DATA_FILE "rsa_encrypted_data.txt"

void ocall_print_string(const char *str)
{
    /* Proxy/Bridge will check the length and null-terminate 
     * the input string to prevent buffer overflow. 
     */
    printf("%s\n", str);
}

void ocall_print_num(uint32_t *num)
{
    std::cout << *num << std::endl;
}

static size_t get_file_size(const char *filename)
{
    std::ifstream ifs(filename, std::ios::in | std::ios::binary);
    if (!ifs.good())
    {
        std::cout << "Failed to open the file \"" << filename << "\"" << std::endl;
        return -1;
    }
    ifs.seekg(0, std::ios::end);
    size_t size = (size_t)ifs.tellg();
    return size;
}

static bool read_file_to_buf(const char *filename, uint8_t *buf, size_t bsize)
{
    if (filename == NULL || buf == NULL || bsize == 0)
        return false;
    std::ifstream ifs(filename, std::ios::binary | std::ios::in);
    if (!ifs.good())
    {
        std::cout << "Failed to open the file \"" << filename << "\"" << std::endl;
        return false;
    }
    ifs.read(reinterpret_cast<char *> (buf), bsize);
    if (ifs.fail())
    {
        std::cout << "Failed to read the file \"" << filename << "\"" << std::endl;
        return false;
    }
    return true;
}

static bool write_buf_to_file(const char *filename, const uint8_t *buf, size_t bsize, long offset)
{
    if (filename == NULL || buf == NULL || bsize == 0)
        return false;
    std::ofstream ofs(filename, std::ios::binary | std::ios::out);
    if (!ofs.good())
    {
        std::cout << "Failed to open the file \"" << filename << "\"" << std::endl;
        return false;
    }
    ofs.seekp(offset, std::ios::beg);
    ofs.write(reinterpret_cast<const char*>(buf), bsize);
    if (ofs.fail())
    {
        std::cout << "Failed to write the file \"" << filename << "\"" << std::endl;
        return false;
    }

    return true;
}

/* Initialize the enclave:
*   Call sgx_create_enclave to initialize an enclave instance
*/
static sgx_status_t initialize_enclave(const char* enclave_path, sgx_enclave_id_t *eid)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    /* Call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */
    ret = sgx_create_enclave(enclave_path, SGX_DEBUG_FLAG, NULL, NULL, eid, NULL);
    if (ret != SGX_SUCCESS) {
        return ret;
    }
    return SGX_SUCCESS;
}


static bool seal_and_save_data()
{
    sgx_enclave_id_t eid_seal = 0;
    // Load the enclave for sealing
    sgx_status_t ret = initialize_enclave(ENCLAVE_NAME_SEAL, &eid_seal);
    if (ret != SGX_SUCCESS)
    {
        ret_error_support(ret);
        return false;
    }

    // Read the origin data from the file
    size_t fsize_mac = get_file_size(ORIGIN_MAC_TEXT);
    if (fsize_mac == (size_t)-1)
    {
        std::cout << "Failed to get the file size of \"" << ORIGIN_MAC_TEXT << "\"" << std::endl;
        sgx_destroy_enclave(eid_seal);
        return false;
    }
    uint8_t *temp_buf_mac = (uint8_t *)malloc(fsize_mac);
    if(temp_buf_mac == NULL)
    {
        std::cout << "Out of memory" << std::endl;
        sgx_destroy_enclave(eid_seal);
        return false;
    }
    if (read_file_to_buf(ORIGIN_MAC_TEXT, temp_buf_mac, fsize_mac) == false)
    {
        std::cout << "Failed to read the origin mac text from \"" << ORIGIN_MAC_TEXT << "\"" << std::endl;
        free(temp_buf_mac);
        sgx_destroy_enclave(eid_seal);
        return false;
    }

    size_t fsize_data = get_file_size(ORIGIN_DATA);
    if (fsize_data == (size_t)-1)
    {
        std::cout << "Failed to get the file size of \"" << ORIGIN_DATA << "\"" << std::endl;
        sgx_destroy_enclave(eid_seal);
        return false;
    }
    uint8_t *temp_buf_data = (uint8_t *)malloc(fsize_data);
    if(temp_buf_data == NULL)
    {
        std::cout << "Out of memory" << std::endl;
        sgx_destroy_enclave(eid_seal);
        return false;
    }
    if (read_file_to_buf(ORIGIN_DATA, temp_buf_data, fsize_data) == false)
    {
        std::cout << "Failed to read the origin data from \"" << ORIGIN_DATA << "\"" << std::endl;
        free(temp_buf_data);
        sgx_destroy_enclave(eid_seal);
        return false;
    }

    // Get the sealed data size
    uint32_t sealed_data_size = 0;
    ret = get_sealed_data_size(eid_seal, &sealed_data_size, &fsize_mac, &fsize_data);
    if (ret != SGX_SUCCESS)
    {
        ret_error_support(ret);
        sgx_destroy_enclave(eid_seal);
        return false;
    }
    else if(sealed_data_size == UINT32_MAX)
    {
        sgx_destroy_enclave(eid_seal);
        return false;
    }
    
    uint8_t *temp_sealed_buf = (uint8_t *)malloc(sealed_data_size);
    if(temp_sealed_buf == NULL)
    {
        std::cout << "Out of memory" << std::endl;
        sgx_destroy_enclave(eid_seal);
        return false;
    }
    sgx_status_t retval;
    ret = seal_data(eid_seal, &retval, temp_buf_mac, fsize_mac, temp_buf_data, fsize_data, temp_sealed_buf, sealed_data_size);
    if (ret != SGX_SUCCESS)
    {
        ret_error_support(ret);
        free(temp_sealed_buf);
        sgx_destroy_enclave(eid_seal);
        return false;
    }
    else if( retval != SGX_SUCCESS)
    {
        ret_error_support(retval);
        free(temp_sealed_buf);
        sgx_destroy_enclave(eid_seal);
        return false;
    }

    // Save the sealed blob
    if (write_buf_to_file(SEALED_DATA_FILE, temp_sealed_buf, sealed_data_size, 0) == false)
    {
        std::cout << "Failed to save the sealed data blob to \"" << SEALED_DATA_FILE << "\"" << std::endl;
        free(temp_sealed_buf);
        sgx_destroy_enclave(eid_seal);
        return false;
    }

    free(temp_sealed_buf);
    free(temp_buf_mac);
    free(temp_buf_data);
    sgx_destroy_enclave(eid_seal);

    std::cout << "Sealing data succeeded." << std::endl;
    return true;

}

static bool generate_key_and_seal()
{
    sgx_enclave_id_t eid_seal = 0;
    // Load the enclave for sealing
    sgx_status_t ret = initialize_enclave(ENCLAVE_NAME_SEAL, &eid_seal);
    if (ret != SGX_SUCCESS)
    {
        ret_error_support(ret);
        return false;
    }

    size_t fsize_mac = 0;
    size_t fsize_data = 16;

    // Get the sealed data size
    uint32_t sealed_data_size = 0;
    ret = get_sealed_data_size(eid_seal, &sealed_data_size, &fsize_mac, &fsize_data);
    if (ret != SGX_SUCCESS)
    {
        ret_error_support(ret);
        sgx_destroy_enclave(eid_seal);
        return false;
    }
    else if(sealed_data_size == UINT32_MAX)
    {
        sgx_destroy_enclave(eid_seal);
        return false;
    }
    
    uint8_t *temp_sealed_buf = (uint8_t *)malloc(sealed_data_size);
    if(temp_sealed_buf == NULL)
    {
        std::cout << "Out of memory" << std::endl;
        sgx_destroy_enclave(eid_seal);
        return false;
    }
    sgx_status_t retval;
    ret = generate_aes_key_and_seal(eid_seal, &retval, temp_sealed_buf, sealed_data_size);
    if (ret != SGX_SUCCESS)
    {
        ret_error_support(ret);
        free(temp_sealed_buf);
        sgx_destroy_enclave(eid_seal);
        return false;
    }
    else if( retval != SGX_SUCCESS)
    {
        ret_error_support(retval);
        free(temp_sealed_buf);
        sgx_destroy_enclave(eid_seal);
        return false;
    }

    // Save the sealed blob
    if (write_buf_to_file(SEALED_KEY_FILE, temp_sealed_buf, sealed_data_size, 0) == false)
    {
        std::cout << "Failed to save the sealed key to \"" << SEALED_KEY_FILE << "\"" << std::endl;
        free(temp_sealed_buf);
        sgx_destroy_enclave(eid_seal);
        return false;
    }

    free(temp_sealed_buf);
    sgx_destroy_enclave(eid_seal);

    std::cout << "generate aes key succeeded." << std::endl;
    return true;
}

static bool generate_rsa_keypair_and_seal()
{
    sgx_enclave_id_t eid_seal = 0;
    // Load the enclave for sealing
    sgx_status_t ret = initialize_enclave(ENCLAVE_NAME_SEAL, &eid_seal);
    if (ret != SGX_SUCCESS)
    {
        ret_error_support(ret);
        return false;
    }

    size_t fsize_mac = 0;
    size_t fsize_prikey = sizeof(sgx_rsa3072_key_t);

    // Get the sealed data size
    uint32_t sealed_data_size = 0;
    ret = get_sealed_data_size(eid_seal, &sealed_data_size, &fsize_mac, &fsize_prikey);
    if (ret != SGX_SUCCESS)
    {
        ret_error_support(ret);
        sgx_destroy_enclave(eid_seal);
        return false;
    }
    else if(sealed_data_size == UINT32_MAX)
    {
        sgx_destroy_enclave(eid_seal);
        return false;
    }
    
    uint8_t *temp_sealed_buf = (uint8_t *)malloc(sealed_data_size);
    if(temp_sealed_buf == NULL)
    {
        std::cout << "Out of memory" << std::endl;
        sgx_destroy_enclave(eid_seal);
        return false;
    }
    unsigned char* p_n = (unsigned char*)malloc(384);
    sgx_status_t retval;
    ret = generate_rsa_key_and_seal(eid_seal, &retval, p_n, temp_sealed_buf, sealed_data_size);
    if (ret != SGX_SUCCESS)
    {
        std::cout << "Error: ret is not success." << std::endl;
        ret_error_support(ret);
        free(temp_sealed_buf);
        sgx_destroy_enclave(eid_seal);
        return false;
    }
    else if( retval != SGX_SUCCESS)
    {
        std::cout << "Error: retval is not success." << std::endl;
        ret_error_support(retval);
        free(temp_sealed_buf);
        sgx_destroy_enclave(eid_seal);
        return false;
    }

    // Save the factor n
    if (write_buf_to_file(RSA_FACTOR_N_FILE, p_n, 384, 0) == false)
    {
        std::cout << "Failed to save the pubkey to \"" << RSA_FACTOR_N_FILE << "\"" << std::endl;
        free(p_n);
        sgx_destroy_enclave(eid_seal);
        return false;
    }

    // Save the sealed blob
    if (write_buf_to_file(SEALED_RSA_PRI_KEY_FILE, temp_sealed_buf, sealed_data_size, 0) == false)
    {
        std::cout << "Failed to save the sealed prikey to \"" << SEALED_RSA_PRI_KEY_FILE << "\"" << std::endl;
        free(temp_sealed_buf);
        sgx_destroy_enclave(eid_seal);
        return false;
    }

    free(p_n);
    free(temp_sealed_buf);
    sgx_destroy_enclave(eid_seal);

    std::cout << "generate rsa keypair succeeded." << std::endl;
    return true;
}

static bool encrypt_by_rsa()
{
    sgx_enclave_id_t eid_seal = 0;
    // Load the enclave for sealing
    sgx_status_t ret = initialize_enclave(ENCLAVE_NAME_SEAL, &eid_seal);
    if (ret != SGX_SUCCESS)
    {
        ret_error_support(ret);
        return false;
    }

    // Read the origin data from the file
    size_t fsize_data = get_file_size(ORIGIN_DATA);
    if (fsize_data == (size_t)-1)
    {
        std::cout << "Failed to get the file size of \"" << ORIGIN_DATA << "\"" << std::endl;
        sgx_destroy_enclave(eid_seal);
        return false;
    }
    uint8_t *temp_buf_data = (uint8_t *)malloc(fsize_data);
    if(temp_buf_data == NULL)
    {
        std::cout << "Out of memory" << std::endl;
        sgx_destroy_enclave(eid_seal);
        return false;
    }
    if (read_file_to_buf(ORIGIN_DATA, temp_buf_data, fsize_data) == false)
    {
        std::cout << "Failed to read the origin data from \"" << ORIGIN_DATA << "\"" << std::endl;
        free(temp_buf_data);
        sgx_destroy_enclave(eid_seal);
        return false;
    }

    // Read the pubkey from the file
    size_t fsize_n = get_file_size(RSA_FACTOR_N_FILE);
    if (fsize_n == (size_t)-1)
    {
        std::cout << "Failed to get the file size of \"" << RSA_FACTOR_N_FILE << "\"" << std::endl;
        sgx_destroy_enclave(eid_seal);
        return false;
    }
    uint8_t *temp_buf_n = (uint8_t *)malloc(fsize_n);
    if(temp_buf_n == NULL)
    {
        std::cout << "Out of memory" << std::endl;
        sgx_destroy_enclave(eid_seal);
        return false;
    }
    if (read_file_to_buf(RSA_FACTOR_N_FILE, temp_buf_n, fsize_n) == false)
    {
        std::cout << "Failed to read the pubkey from \"" << RSA_FACTOR_N_FILE << "\"" << std::endl;
        free(temp_buf_n);
        sgx_destroy_enclave(eid_seal);
        return false;
    }

    sgx_status_t retval;
    size_t encrypted_data_size = 0;
    ret = encrypt_by_rsa_pubkey(eid_seal, &retval, temp_buf_n, temp_buf_data, fsize_data, NULL, &encrypted_data_size);
    uint8_t *temp_encrypted_buf = (uint8_t *)malloc(encrypted_data_size);
    ret = encrypt_by_rsa_pubkey(eid_seal, &retval, temp_buf_n, temp_buf_data, fsize_data, temp_encrypted_buf, &encrypted_data_size);

    if (ret != SGX_SUCCESS)
    {
        std::cout << "Error: ret is not success." << std::endl;
        ret_error_support(ret);
        free(temp_encrypted_buf);
        sgx_destroy_enclave(eid_seal);
        return false;
    }
    else if( retval != SGX_SUCCESS)
    {
        std::cout << "Error: retval is not success." << std::endl;
        ret_error_support(retval);
        free(temp_encrypted_buf);
        sgx_destroy_enclave(eid_seal);
        return false;
    }

    if(encrypted_data_size != 0)
    {
        std::cout << "encrypted_data_size: " << encrypted_data_size << std::endl;
    } else {
        std::cout << "encrypted_data_size is NULL" << std::endl;
    }

    // Save the encrypted data
    if (write_buf_to_file(RSA_ENCRYPTED_DATA_FILE, temp_encrypted_buf, encrypted_data_size, 0) == false)
    {
        std::cout << "Failed to save the rsa encrypted data to \"" << RSA_ENCRYPTED_DATA_FILE << "\"" << std::endl;
        free(temp_encrypted_buf);
        sgx_destroy_enclave(eid_seal);
        return false;
    }

    free(temp_encrypted_buf);
    free(temp_buf_data);
    sgx_destroy_enclave(eid_seal);

    std::cout << "Encrypt by rsa succeeded." << std::endl;
    return true;
}

//TODO : Implement the function decrypt_by_rsa
static bool decrypt_by_rsa()
{
    // sgx_enclave_id_t eid_seal = 0;
    // // Load the enclave for sealing
    // sgx_status_t ret = initialize_enclave(ENCLAVE_NAME_SEAL, &eid_seal);
    // if (ret != SGX_SUCCESS)
    // {
    //     ret_error_support(ret);
    //     return false;
    // }

    // // Read the origin data from the file
    // size_t fsize_data = get_file_size(ORIGIN_DATA);
    // if (fsize_data == (size_t)-1)
    // {
    //     std::cout << "Failed to get the file size of \"" << ORIGIN_DATA << "\"" << std::endl;
    //     sgx_destroy_enclave(eid_seal);
    //     return false;
    // }
    // uint8_t *temp_buf_data = (uint8_t *)malloc(fsize_data);
    // if(temp_buf_data == NULL)
    // {
    //     std::cout << "Out of memory" << std::endl;
    //     sgx_destroy_enclave(eid_seal);
    //     return false;
    // }
    // if (read_file_to_buf(ORIGIN_DATA, temp_buf_data, fsize_data) == false)
    // {
    //     std::cout << "Failed to read the origin data from \"" << ORIGIN_DATA << "\"" << std::endl;
    //     free(temp_buf_data);
    //     sgx_destroy_enclave(eid_seal);
    //     return false;
    // }

    // // Read the pubkey from the file
    // size_t fsize_n = get_file_size(RSA_FACTOR_N_FILE);
    // if (fsize_n == (size_t)-1)
    // {
    //     std::cout << "Failed to get the file size of \"" << RSA_FACTOR_N_FILE << "\"" << std::endl;
    //     sgx_destroy_enclave(eid_seal);
    //     return false;
    // }
    // uint8_t *temp_buf_n = (uint8_t *)malloc(fsize_n);
    // if(temp_buf_n == NULL)
    // {
    //     std::cout << "Out of memory" << std::endl;
    //     sgx_destroy_enclave(eid_seal);
    //     return false;
    // }
    // if (read_file_to_buf(RSA_FACTOR_N_FILE, temp_buf_n, fsize_n) == false)
    // {
    //     std::cout << "Failed to read the pubkey from \"" << RSA_FACTOR_N_FILE << "\"" << std::endl;
    //     free(temp_buf_n);
    //     sgx_destroy_enclave(eid_seal);
    //     return false;
    // }

    // sgx_status_t retval;
    // size_t encrypted_data_size = 0;
    // ret = encrypt_by_rsa_pubkey(eid_seal, &retval, temp_buf_n, temp_buf_data, fsize_data, NULL, &encrypted_data_size);
    // uint8_t *temp_encrypted_buf = (uint8_t *)malloc(encrypted_data_size);
    // ret = encrypt_by_rsa_pubkey(eid_seal, &retval, temp_buf_n, temp_buf_data, fsize_data, temp_encrypted_buf, &encrypted_data_size);

    // if (ret != SGX_SUCCESS)
    // {
    //     std::cout << "Error: ret is not success." << std::endl;
    //     ret_error_support(ret);
    //     free(temp_encrypted_buf);
    //     sgx_destroy_enclave(eid_seal);
    //     return false;
    // }
    // else if( retval != SGX_SUCCESS)
    // {
    //     std::cout << "Error: retval is not success." << std::endl;
    //     ret_error_support(retval);
    //     free(temp_encrypted_buf);
    //     sgx_destroy_enclave(eid_seal);
    //     return false;
    // }

    // if(encrypted_data_size != 0)
    // {
    //     std::cout << "encrypted_data_size: " << encrypted_data_size << std::endl;
    // } else {
    //     std::cout << "encrypted_data_size is NULL" << std::endl;
    // }

    // // Save the encrypted data
    // if (write_buf_to_file(RSA_ENCRYPTED_DATA_FILE, temp_encrypted_buf, encrypted_data_size, 0) == false)
    // {
    //     std::cout << "Failed to save the rsa encrypted data to \"" << RSA_ENCRYPTED_DATA_FILE << "\"" << std::endl;
    //     free(temp_encrypted_buf);
    //     sgx_destroy_enclave(eid_seal);
    //     return false;
    // }

    // free(temp_encrypted_buf);
    // free(temp_buf_data);
    // sgx_destroy_enclave(eid_seal);

    // std::cout << "Encrypt by rsa succeeded." << std::endl;
    // return true;
}

static bool read_and_unseal_data()
{
    sgx_enclave_id_t eid_unseal = 0;
    // Load the enclave for unsealing
    sgx_status_t ret = initialize_enclave(ENCLAVE_NAME_UNSEAL, &eid_unseal);
    if (ret != SGX_SUCCESS)
    {
        ret_error_support(ret);
        return false;
    }
    
    // Read the sealed blob from the file
    size_t fsize = get_file_size(SEALED_DATA_FILE);
    if (fsize == (size_t)-1)
    {
        std::cout << "Failed to get the file size of \"" << SEALED_DATA_FILE << "\"" << std::endl;
        sgx_destroy_enclave(eid_unseal);
        return false;
    }
    uint8_t *temp_buf = (uint8_t *)malloc(fsize);
    if(temp_buf == NULL)
    {
        std::cout << "Out of memory" << std::endl;
        sgx_destroy_enclave(eid_unseal);
        return false;
    }
    if (read_file_to_buf(SEALED_DATA_FILE, temp_buf, fsize) == false)
    {
        std::cout << "Failed to read the sealed data blob from \"" << SEALED_DATA_FILE << "\"" << std::endl;
        free(temp_buf);
        sgx_destroy_enclave(eid_unseal);
        return false;
    }

    // Get the sealed data size
    uint32_t unsealed_mac_text_size = 0;
    uint32_t unsealed_decrypt_data_size = 0;
    ret = get_unsealed_data_size(eid_unseal, temp_buf, fsize, &unsealed_mac_text_size, &unsealed_decrypt_data_size);
    if (ret != SGX_SUCCESS)
    {
        ret_error_support(ret);
        free(temp_buf);
        sgx_destroy_enclave(eid_unseal);
        return false;
    }
    else if(unsealed_mac_text_size == UINT32_MAX || unsealed_decrypt_data_size == UINT32_MAX)
    {
        free(temp_buf);
        sgx_destroy_enclave(eid_unseal);
        return false;
    }

    uint8_t *temp_mac_text = (uint8_t *)malloc(unsealed_mac_text_size);
    uint8_t *temp_decrypt_data = (uint8_t *)malloc(unsealed_decrypt_data_size);
    if(temp_mac_text == NULL || temp_decrypt_data == NULL)
    {
        std::cout << "Out of memory" << std::endl;
        free(temp_mac_text);
        free(temp_decrypt_data);
        free(temp_buf);
        sgx_destroy_enclave(eid_unseal);
        return false;
    }

    // Unseal the sealed blob
    sgx_status_t retval;
    ret = unseal_data(eid_unseal, &retval, temp_buf, fsize, temp_mac_text, unsealed_mac_text_size, temp_decrypt_data, unsealed_decrypt_data_size);
    if (ret != SGX_SUCCESS)
    {
        ret_error_support(ret);
        free(temp_buf);
        sgx_destroy_enclave(eid_unseal);
        return false;
    }
    else if(retval != SGX_SUCCESS)
    {
        ret_error_support(retval);
        free(temp_buf);
        sgx_destroy_enclave(eid_unseal);
        return false;
    }

    // Save the Unsealed data
    if (write_buf_to_file(UNSEALED_MAC_TEXT, temp_mac_text, unsealed_mac_text_size, 0) == false)
    {
        std::cout << "Failed to save the unsealed mac text to \"" << UNSEALED_MAC_TEXT << "\"" << std::endl;
        free(temp_mac_text);
        sgx_destroy_enclave(eid_unseal);
        return false;
    }

    if (write_buf_to_file(UNSEALED_DECRYPT_DATA, temp_decrypt_data, unsealed_decrypt_data_size, 0) == false)
    {
        std::cout << "Failed to save the unsealed decrypt data to \"" << UNSEALED_DECRYPT_DATA << "\"" << std::endl;
        free(temp_decrypt_data);
        sgx_destroy_enclave(eid_unseal);
        return false;
    }

    free(temp_buf);
    free(temp_mac_text);
    free(temp_decrypt_data);
    sgx_destroy_enclave(eid_unseal);
   
    std::cout << "Unseal succeeded." << std::endl;
    return true;
}


int main(int argc, char* argv[])
{
    (void)argc, (void)argv;

    // // Enclave_Seal: seal the secret and save the data blob to a file
    // if (seal_and_save_data() == false)
    // {
    //     std::cout << "Failed to seal the secret and save it to a file." << std::endl;
    //     return -1;
    // }

    // // Enclave_Unseal: read the data blob from the file and unseal it.
    // if (read_and_unseal_data() == false)
    // {
    //     std::cout << "Failed to unseal the data blob." << std::endl;
    //     return -1;
    // }

    // if(generate_key_and_seal() == false)
    // {
    //     std::cout << "Failed to generate and seal the data blob." << std::endl;
    //     return -1;
    // }

    if(generate_rsa_keypair_and_seal() == false)
    {
        std::cout << "Failed to generate rsa keypair." << std::endl;
        return -1;
    }

    if(encrypt_by_rsa() == false)
    {
        std::cout << "Failed to encrypt by rsa." << std::endl;
        return -1;
    }

    return 0;
}

