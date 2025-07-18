#ifndef ENCLAVE_SEAL_U_H__
#define ENCLAVE_SEAL_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_status_t etc. */

#include "sgx_report.h"
#include "stdbool.h"
#include "/root/sgx-gmp-lib/include/sgx_tgmp.h"
#include "sgx_qve_header.h"
#include "sgx_ql_quote.h"
#include "sgx_dcap_qal.h"
#include "sgx_dcap_qae_tvl.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

#ifndef OCALL_PRINT_STRING_DEFINED__
#define OCALL_PRINT_STRING_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_print_string, (const char* str));
#endif
#ifndef OCALL_PRINT_NUM_DEFINED__
#define OCALL_PRINT_NUM_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_print_num, (uint32_t* num));
#endif
#ifndef OCALL_PRINT_MPZ_DEFINED__
#define OCALL_PRINT_MPZ_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_print_mpz, (mpz_t* num));
#endif
#ifndef SGX_OC_CPUIDEX_DEFINED__
#define SGX_OC_CPUIDEX_DEFINED__
void SGX_UBRIDGE(SGX_CDECL, sgx_oc_cpuidex, (int cpuinfo[4], int leaf, int subleaf));
#endif
#ifndef SGX_THREAD_WAIT_UNTRUSTED_EVENT_OCALL_DEFINED__
#define SGX_THREAD_WAIT_UNTRUSTED_EVENT_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_wait_untrusted_event_ocall, (const void* self));
#endif
#ifndef SGX_THREAD_SET_UNTRUSTED_EVENT_OCALL_DEFINED__
#define SGX_THREAD_SET_UNTRUSTED_EVENT_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_untrusted_event_ocall, (const void* waiter));
#endif
#ifndef SGX_THREAD_SETWAIT_UNTRUSTED_EVENTS_OCALL_DEFINED__
#define SGX_THREAD_SETWAIT_UNTRUSTED_EVENTS_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_setwait_untrusted_events_ocall, (const void* waiter, const void* self));
#endif
#ifndef SGX_THREAD_SET_MULTIPLE_UNTRUSTED_EVENTS_OCALL_DEFINED__
#define SGX_THREAD_SET_MULTIPLE_UNTRUSTED_EVENTS_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_multiple_untrusted_events_ocall, (const void** waiters, size_t total));
#endif

sgx_status_t get_sealed_data_size(sgx_enclave_id_t eid, uint32_t* retval, size_t* aad_mac_text_len, size_t* encrypt_data_len);
sgx_status_t seal_data(sgx_enclave_id_t eid, sgx_status_t* retval, uint8_t* p_aad_mac_text, size_t aad_mac_text_len, uint8_t* p_encrypt_data, size_t encrypt_data_len, uint8_t* sealed_blob, uint32_t data_size);
sgx_status_t generate_aes_key_and_seal(sgx_enclave_id_t eid, sgx_status_t* retval, uint8_t* p_aes_key, uint32_t key_size);
sgx_status_t generate_rsa_key(sgx_enclave_id_t eid, sgx_status_t* retval, unsigned char* p_n, unsigned char* p_d, unsigned char* p_p, unsigned char* p_q, unsigned char* p_dmp1, unsigned char* p_dmq1, unsigned char* p_iqmp);
sgx_status_t encrypt_by_rsa_pubkey(sgx_enclave_id_t eid, sgx_status_t* retval, unsigned char* p_n, unsigned char* p_data, size_t data_size, unsigned char* p_encrypt_data, size_t encrypt_data_size);
sgx_status_t get_unsealed_data_size(sgx_enclave_id_t eid, const uint8_t* sealed_blob, size_t data_size, uint32_t* p_mac_text_len, uint32_t* p_decrypt_data_len);
sgx_status_t unseal_data(sgx_enclave_id_t eid, sgx_status_t* retval, const uint8_t* sealed_blob, size_t data_size, uint8_t* p_mac_text, size_t mac_data_size, uint8_t* p_decrypt_data, size_t decrypt_data_size);
sgx_status_t decrypt_by_rsa_prikey(sgx_enclave_id_t eid, sgx_status_t* retval, unsigned char* p_p, unsigned char* p_q, unsigned char* p_dmp1, unsigned char* p_dmq1, unsigned char* p_iqmp, uint8_t* p_data, size_t data_size, uint8_t* p_decrypt_data, size_t decrypt_data_size);
sgx_status_t sign_data_with_rsa(sgx_enclave_id_t eid, sgx_status_t* retval, unsigned char* p_n, unsigned char* p_d, uint8_t* p_data, size_t data_len, uint8_t* p_sig);
sgx_status_t verify_signature_with_rsa(sgx_enclave_id_t eid, sgx_status_t* retval, unsigned char* p_n, uint8_t* p_data, size_t data_len, uint8_t* p_sig, uint8_t* is_valid);
sgx_status_t forge(sgx_enclave_id_t eid, char* s, char* q, char* t, char* r, char* t_new, char* r_new);
sgx_status_t enclave_create_report(sgx_enclave_id_t eid, uint32_t* retval, const sgx_target_info_t* p_qe3_target, sgx_report_t* p_report);
sgx_status_t ecall_get_target_info(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_target_info_t* target_info);
sgx_status_t generate_encrypt_and_report(sgx_enclave_id_t eid, bool* retval, sgx_target_info_t* p_qe_target_info, unsigned char* encrypted_p, size_t encrypted_p_len, unsigned char* encrypted_q, size_t encrypted_q_len, unsigned char* encrypted_dmp1, size_t encrypted_dmp1_len, unsigned char* encrypted_dmq1, size_t encrypted_dmq1_len, unsigned char* encrypted_iqmp, size_t encrypted_iqmp_len, sgx_report_t* p_report);
sgx_status_t sys_prikey_cal(sgx_enclave_id_t eid, char* s, char* q, char* s_sys);
sgx_status_t sgx_tvl_verify_qve_report_and_identity(sgx_enclave_id_t eid, quote3_error_t* retval, const uint8_t* p_quote, uint32_t quote_size, const sgx_ql_qe_report_info_t* p_qve_report_info, time_t expiration_check_date, uint32_t collateral_expiration_status, sgx_ql_qv_result_t quote_verification_result, const uint8_t* p_supplemental_data, uint32_t supplemental_data_size, sgx_isv_svn_t qve_isvsvn_threshold);
sgx_status_t tee_verify_qae_report_and_identity(sgx_enclave_id_t eid, quote3_error_t* retval, qae_verification_input_t* input, sgx_ql_qe_report_info_t qae_report_info, sgx_isv_svn_t qae_isvsvn_threshold);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
