// App.cpp : Define the entry point for the console application.
//

#include <string.h>
#include <assert.h>
#include <fstream>
#include <thread>
#include <iostream>

#include "sgx_urts.h"
#include "Enclave_Seal_u.h"

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
#define RSA_FACTOR_N "rsa_factor_n.txt"
#define RSA_FACTOR_P "rsa_factor_p.txt"
#define RSA_FACTOR_Q "rsa_factor_q.txt"
#define RSA_FACTOR_DMP1 "rsa_factor_dmp1.txt"
#define RSA_FACTOR_DMQ1 "rsa_factor_dmq1.txt"
#define RSA_FACTOR_IQMP "rsa_factor_iqmp.txt"
#define RSA_FACTOR_FILE "rsa_factor.txt"
#define RSA_ENCRYPTED_DATA_FILE "rsa_encrypted_data.txt"
#define RSA_DECRYPTED_DATA_FILE "rsa_decrypted_data.txt"

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

static bool read_file_to_batch_buf(const char *filename, uint8_t* bufs[], size_t bsize, size_t batch_size)
{
    std::ifstream ifs(filename, std::ios::binary | std::ios::in);
    for(size_t i = 0; i < batch_size; i++)
    {
        if (filename == NULL || bufs[i] == NULL || bsize == 0)
            return false;
        if (!ifs.good())
        {
            std::cout << "Failed to open the file \"" << filename << "\"" << std::endl;
            return false;
        }
        ifs.read(reinterpret_cast<char *> (bufs[i]), bsize);
        if (ifs.fail())
        {
            std::cout << "Failed to read the file \"" << filename << "\"" << std::endl;
            return false;
        }
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

static bool write_batch_buf_to_file(const char *filename, uint8_t* bufs[], size_t bsize, size_t batch_size, long offset)
{
    std::ofstream ofs(filename, std::ios::binary | std::ios::out);
    for(size_t i = 0; i < batch_size; i++)
    {
        if (filename == NULL || bufs[i] == NULL || bsize == 0)
            return false;
        if (!ofs.good())
        {
            std::cout << "Failed to open the file \"" << filename << "\"" << std::endl;
            return false;
        }
        ofs.seekp(offset * i, std::ios::beg);
        ofs.write(reinterpret_cast<const char*>(bufs[i]), bsize);
        if (ofs.fail())
        {
            std::cout << "Failed to write the file \"" << filename << "\"" << std::endl;
            return false;
        }
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

    unsigned char* n = (unsigned char*)malloc(384);
    unsigned char* p = (unsigned char*)malloc(192);
    unsigned char* q = (unsigned char*)malloc(192);
    unsigned char* dmp1 = (unsigned char*)malloc(192);
    unsigned char* dmq1 = (unsigned char*)malloc(192);
    unsigned char* iqmp = (unsigned char*)malloc(192);

    sgx_status_t retval;

    ret = generate_rsa_key_and_seal(eid_seal, &retval, n, p, q, dmp1, dmq1, iqmp);
    if (ret != SGX_SUCCESS)
    {
        std::cout << "Error: ret is not success." << std::endl;
        ret_error_support(ret);
        sgx_destroy_enclave(eid_seal);
        return false;
    }
    else if( retval != SGX_SUCCESS)
    {
        std::cout << "Error: retval is not success." << std::endl;
        ret_error_support(retval);
        sgx_destroy_enclave(eid_seal);
        return false;
    }

    // Save the factors
    if (write_buf_to_file(RSA_FACTOR_N, n, 384, 0) == false ||
        write_buf_to_file(RSA_FACTOR_P, p, 192, 0) == false ||
        write_buf_to_file(RSA_FACTOR_Q, q, 192, 0) == false ||
        write_buf_to_file(RSA_FACTOR_DMP1, dmp1, 192, 0) == false ||
        write_buf_to_file(RSA_FACTOR_DMQ1, dmq1, 192, 0) == false ||
        write_buf_to_file(RSA_FACTOR_IQMP, iqmp, 192, 0) == false ){
        std::cout << "Failed to save the params " << "to \"" << "\"" << std::endl;
        sgx_destroy_enclave(eid_seal);
        return false;
    }

    free(n);
    free(p);
    free(q);
    free(dmp1);
    free(dmq1);
    free(iqmp);

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

    std::cout << "fsize_data: " << fsize_data << std::endl;

    // Read the pubkey from the file
    size_t fsize_n = 384;
    uint8_t *temp_buf_n = (uint8_t *)malloc(fsize_n);
    if(temp_buf_n == NULL)
    {
        std::cout << "Out of memory" << std::endl;
        sgx_destroy_enclave(eid_seal);
        return false;
    }
    if (read_file_to_buf(RSA_FACTOR_N, temp_buf_n, fsize_n) == false)
    {
        std::cout << "Failed to read the pubkey from \"" << RSA_FACTOR_FILE << "\"" << std::endl;
        free(temp_buf_n);
        sgx_destroy_enclave(eid_seal);
        return false;
    }

    sgx_status_t retval;
    size_t encrypted_data_size = 384;
    unsigned char* temp_encrypted_buf = (unsigned char*)malloc(encrypted_data_size);
    ret = encrypt_by_rsa_pubkey(eid_seal, &retval, temp_buf_n, temp_buf_data, fsize_data, temp_encrypted_buf, encrypted_data_size);

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

    free(temp_buf_n);
    free(temp_buf_data);
    free(temp_encrypted_buf);

    sgx_destroy_enclave(eid_seal);

    std::cout << "Encrypt by rsa succeeded." << std::endl;
    return true;
}

static bool decrypt_by_rsa()
{
    sgx_enclave_id_t eid_seal = 0;
    // Load the enclave for sealing
    sgx_status_t ret = initialize_enclave(ENCLAVE_NAME_SEAL, &eid_seal);
    if (ret != SGX_SUCCESS)
    {
        ret_error_support(ret);
        return false;
    }

    // Read the encrypted data from the file
    size_t fsize_data = get_file_size(RSA_ENCRYPTED_DATA_FILE);
    if (fsize_data == (size_t)-1)
    {
        std::cout << "Failed to get the file size of \"" << RSA_ENCRYPTED_DATA_FILE << "\"" << std::endl;
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
    if (read_file_to_buf(RSA_ENCRYPTED_DATA_FILE, temp_buf_data, fsize_data) == false)
    {
        std::cout << "Failed to read the origin data from \"" << RSA_ENCRYPTED_DATA_FILE << "\"" << std::endl;
        free(temp_buf_data);
        sgx_destroy_enclave(eid_seal);
        return false;
    }

    // Read the factor from the file
    size_t fsize = 192;
    unsigned char *temp_buf_p = (unsigned char *)malloc(fsize);
    unsigned char *temp_buf_q = (unsigned char *)malloc(fsize);
    unsigned char *temp_buf_dmp1 = (unsigned char *)malloc(fsize);
    unsigned char *temp_buf_dmq1 = (unsigned char *)malloc(fsize);
    unsigned char *temp_buf_iqmp = (unsigned char *)malloc(fsize);
    if(temp_buf_p == NULL || temp_buf_q == NULL || temp_buf_dmp1 == NULL || temp_buf_dmq1 == NULL || temp_buf_iqmp == NULL)
    {
        std::cout << "Out of memory" << std::endl;
        sgx_destroy_enclave(eid_seal);
        return false;
    }
    if (read_file_to_buf(RSA_FACTOR_P, temp_buf_p, fsize) == false ||
        read_file_to_buf(RSA_FACTOR_Q, temp_buf_q, fsize) == false ||
        read_file_to_buf(RSA_FACTOR_DMP1, temp_buf_dmp1, fsize) == false ||
        read_file_to_buf(RSA_FACTOR_DMQ1, temp_buf_dmq1, fsize) == false ||
        read_file_to_buf(RSA_FACTOR_IQMP, temp_buf_iqmp, fsize) == false)
    {
        std::cout << "Failed to read the factor from \""  << "\"" << std::endl;
        free(temp_buf_p);
        free(temp_buf_q);
        free(temp_buf_dmp1);
        free(temp_buf_dmq1);
        free(temp_buf_iqmp);
        sgx_destroy_enclave(eid_seal);
        return false;
    }
    
    sgx_status_t retval;
    size_t decrypted_data_size = 384;
    unsigned char* temp_decrypted_buf = (unsigned char*)malloc(decrypted_data_size);
    ret = decrypt_by_rsa_prikey(eid_seal, &retval, temp_buf_p, temp_buf_q, temp_buf_dmp1, temp_buf_dmq1, temp_buf_iqmp, temp_buf_data, fsize_data, temp_decrypted_buf, decrypted_data_size);

    if (ret != SGX_SUCCESS)
    {
        std::cout << "Error: ret is not success." << std::endl;
        ret_error_support(ret);
        free(temp_decrypted_buf);
        sgx_destroy_enclave(eid_seal);
        return false;
    }
    else if( retval != SGX_SUCCESS)
    {
        std::cout << "Error: retval is not success." << std::endl;
        ret_error_support(retval);
        free(temp_decrypted_buf);
        sgx_destroy_enclave(eid_seal);
        return false;
    }

    // Save the decrypted data
    if (write_buf_to_file(RSA_DECRYPTED_DATA_FILE, temp_decrypted_buf, decrypted_data_size, 0) == false)
    {
        std::cout << "Failed to save the rsa decrypted data to \"" << RSA_DECRYPTED_DATA_FILE << "\"" << std::endl;
        free(temp_decrypted_buf);
        sgx_destroy_enclave(eid_seal);
        return false;
    }

    free(temp_buf_p);
    free(temp_buf_q);
    free(temp_buf_dmp1);
    free(temp_buf_dmq1);
    free(temp_buf_iqmp);
    free(temp_decrypted_buf);
    free(temp_buf_data);
    sgx_destroy_enclave(eid_seal);

    std::cout << "Decrypt by rsa succeeded." << std::endl;
    return true;
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

    // if (seal_and_save_data() == false)
    // {
    //     std::cout << "Failed to seal the secret and save it to a file." << std::endl;
    //     return -1;
    // }

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

    if(decrypt_by_rsa() == false)
    {
        std::cout << "Failed to decrypt by rsa." << std::endl;
        return -1;
    }

    return 0;
}

