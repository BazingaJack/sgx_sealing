#include "Enclave_Seal_u.h"
#include <errno.h>

typedef struct ms_get_sealed_data_size_t {
	uint32_t ms_retval;
	size_t* ms_aad_mac_text_len;
	size_t* ms_encrypt_data_len;
} ms_get_sealed_data_size_t;

typedef struct ms_seal_data_t {
	sgx_status_t ms_retval;
	uint8_t* ms_p_aad_mac_text;
	size_t ms_aad_mac_text_len;
	uint8_t* ms_p_encrypt_data;
	size_t ms_encrypt_data_len;
	uint8_t* ms_sealed_blob;
	uint32_t ms_data_size;
} ms_seal_data_t;

typedef struct ms_generate_aes_key_and_seal_t {
	sgx_status_t ms_retval;
	uint8_t* ms_p_aes_key;
	uint32_t ms_key_size;
} ms_generate_aes_key_and_seal_t;

typedef struct ms_generate_rsa_key_and_seal_t {
	sgx_status_t ms_retval;
	unsigned char* ms_p_n;
	unsigned char* ms_p_d;
	unsigned char* ms_p_p;
	unsigned char* ms_p_q;
	unsigned char* ms_p_dmp1;
	unsigned char* ms_p_dmq1;
	unsigned char* ms_p_iqmp;
} ms_generate_rsa_key_and_seal_t;

typedef struct ms_encrypt_by_rsa_pubkey_t {
	sgx_status_t ms_retval;
	unsigned char* ms_p_n;
	unsigned char* ms_p_data;
	size_t ms_data_size;
	unsigned char* ms_p_encrypt_data;
	size_t ms_encrypt_data_size;
} ms_encrypt_by_rsa_pubkey_t;

typedef struct ms_get_unsealed_data_size_t {
	const uint8_t* ms_sealed_blob;
	size_t ms_data_size;
	uint32_t* ms_p_mac_text_len;
	uint32_t* ms_p_decrypt_data_len;
} ms_get_unsealed_data_size_t;

typedef struct ms_unseal_data_t {
	sgx_status_t ms_retval;
	const uint8_t* ms_sealed_blob;
	size_t ms_data_size;
	uint8_t* ms_p_mac_text;
	size_t ms_mac_data_size;
	uint8_t* ms_p_decrypt_data;
	size_t ms_decrypt_data_size;
} ms_unseal_data_t;

typedef struct ms_decrypt_by_rsa_prikey_t {
	sgx_status_t ms_retval;
	unsigned char* ms_p_p;
	unsigned char* ms_p_q;
	unsigned char* ms_p_dmp1;
	unsigned char* ms_p_dmq1;
	unsigned char* ms_p_iqmp;
	uint8_t* ms_p_data;
	size_t ms_data_size;
	uint8_t* ms_p_decrypt_data;
	size_t ms_decrypt_data_size;
} ms_decrypt_by_rsa_prikey_t;

typedef struct ms_sign_data_with_rsa_t {
	sgx_status_t ms_retval;
	unsigned char* ms_p_n;
	unsigned char* ms_p_d;
	uint8_t* ms_p_data;
	size_t ms_data_len;
	uint8_t* ms_p_sig;
} ms_sign_data_with_rsa_t;

typedef struct ms_verify_signature_with_rsa_t {
	sgx_status_t ms_retval;
	unsigned char* ms_p_n;
	uint8_t* ms_p_data;
	size_t ms_data_len;
	uint8_t* ms_p_sig;
	uint8_t* ms_is_valid;
} ms_verify_signature_with_rsa_t;

typedef struct ms_forge_t {
	mpz_t* ms_s;
	mpz_t* ms_q;
	mpz_t* ms_t;
	mpz_t* ms_r;
	mpz_t* ms_t_new;
	mpz_t* ms_r_new;
} ms_forge_t;

typedef struct ms_enclave_create_report_t {
	uint32_t ms_retval;
	const sgx_target_info_t* ms_p_qe3_target;
	sgx_report_t* ms_p_report;
} ms_enclave_create_report_t;

typedef struct ms_ecall_get_target_info_t {
	sgx_status_t ms_retval;
	sgx_target_info_t* ms_target_info;
} ms_ecall_get_target_info_t;

typedef struct ms_generate_encrypt_and_report_t {
	bool ms_retval;
	sgx_target_info_t* ms_p_qe_target_info;
	unsigned char* ms_encrypted_p;
	size_t ms_encrypted_p_len;
	unsigned char* ms_encrypted_q;
	size_t ms_encrypted_q_len;
	unsigned char* ms_encrypted_dmp1;
	size_t ms_encrypted_dmp1_len;
	unsigned char* ms_encrypted_dmq1;
	size_t ms_encrypted_dmq1_len;
	unsigned char* ms_encrypted_iqmp;
	size_t ms_encrypted_iqmp_len;
	sgx_report_t* ms_p_report;
} ms_generate_encrypt_and_report_t;

typedef struct ms_sgx_tvl_verify_qve_report_and_identity_t {
	quote3_error_t ms_retval;
	const uint8_t* ms_p_quote;
	uint32_t ms_quote_size;
	const sgx_ql_qe_report_info_t* ms_p_qve_report_info;
	time_t ms_expiration_check_date;
	uint32_t ms_collateral_expiration_status;
	sgx_ql_qv_result_t ms_quote_verification_result;
	const uint8_t* ms_p_supplemental_data;
	uint32_t ms_supplemental_data_size;
	sgx_isv_svn_t ms_qve_isvsvn_threshold;
} ms_sgx_tvl_verify_qve_report_and_identity_t;

typedef struct ms_tee_verify_qae_report_and_identity_t {
	quote3_error_t ms_retval;
	qae_verification_input_t* ms_input;
	sgx_ql_qe_report_info_t ms_qae_report_info;
	sgx_isv_svn_t ms_qae_isvsvn_threshold;
} ms_tee_verify_qae_report_and_identity_t;

typedef struct ms_ocall_print_string_t {
	const char* ms_str;
} ms_ocall_print_string_t;

typedef struct ms_ocall_print_num_t {
	uint32_t* ms_num;
} ms_ocall_print_num_t;

typedef struct ms_ocall_print_mpz_t {
	mpz_t* ms_num;
} ms_ocall_print_mpz_t;

typedef struct ms_sgx_oc_cpuidex_t {
	int* ms_cpuinfo;
	int ms_leaf;
	int ms_subleaf;
} ms_sgx_oc_cpuidex_t;

typedef struct ms_sgx_thread_wait_untrusted_event_ocall_t {
	int ms_retval;
	const void* ms_self;
} ms_sgx_thread_wait_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_set_untrusted_event_ocall_t {
	int ms_retval;
	const void* ms_waiter;
} ms_sgx_thread_set_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_setwait_untrusted_events_ocall_t {
	int ms_retval;
	const void* ms_waiter;
	const void* ms_self;
} ms_sgx_thread_setwait_untrusted_events_ocall_t;

typedef struct ms_sgx_thread_set_multiple_untrusted_events_ocall_t {
	int ms_retval;
	const void** ms_waiters;
	size_t ms_total;
} ms_sgx_thread_set_multiple_untrusted_events_ocall_t;

static sgx_status_t SGX_CDECL Enclave_Seal_ocall_print_string(void* pms)
{
	ms_ocall_print_string_t* ms = SGX_CAST(ms_ocall_print_string_t*, pms);
	ocall_print_string(ms->ms_str);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_Seal_ocall_print_num(void* pms)
{
	ms_ocall_print_num_t* ms = SGX_CAST(ms_ocall_print_num_t*, pms);
	ocall_print_num(ms->ms_num);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_Seal_ocall_print_mpz(void* pms)
{
	ms_ocall_print_mpz_t* ms = SGX_CAST(ms_ocall_print_mpz_t*, pms);
	ocall_print_mpz(ms->ms_num);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_Seal_sgx_oc_cpuidex(void* pms)
{
	ms_sgx_oc_cpuidex_t* ms = SGX_CAST(ms_sgx_oc_cpuidex_t*, pms);
	sgx_oc_cpuidex(ms->ms_cpuinfo, ms->ms_leaf, ms->ms_subleaf);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_Seal_sgx_thread_wait_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_wait_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_wait_untrusted_event_ocall(ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_Seal_sgx_thread_set_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_set_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_untrusted_event_ocall(ms->ms_waiter);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_Seal_sgx_thread_setwait_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_setwait_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_setwait_untrusted_events_ocall(ms->ms_waiter, ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_Seal_sgx_thread_set_multiple_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_multiple_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_multiple_untrusted_events_ocall(ms->ms_waiters, ms->ms_total);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[8];
} ocall_table_Enclave_Seal = {
	8,
	{
		(void*)Enclave_Seal_ocall_print_string,
		(void*)Enclave_Seal_ocall_print_num,
		(void*)Enclave_Seal_ocall_print_mpz,
		(void*)Enclave_Seal_sgx_oc_cpuidex,
		(void*)Enclave_Seal_sgx_thread_wait_untrusted_event_ocall,
		(void*)Enclave_Seal_sgx_thread_set_untrusted_event_ocall,
		(void*)Enclave_Seal_sgx_thread_setwait_untrusted_events_ocall,
		(void*)Enclave_Seal_sgx_thread_set_multiple_untrusted_events_ocall,
	}
};
sgx_status_t get_sealed_data_size(sgx_enclave_id_t eid, uint32_t* retval, size_t* aad_mac_text_len, size_t* encrypt_data_len)
{
	sgx_status_t status;
	ms_get_sealed_data_size_t ms;
	ms.ms_aad_mac_text_len = aad_mac_text_len;
	ms.ms_encrypt_data_len = encrypt_data_len;
	status = sgx_ecall(eid, 0, &ocall_table_Enclave_Seal, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t seal_data(sgx_enclave_id_t eid, sgx_status_t* retval, uint8_t* p_aad_mac_text, size_t aad_mac_text_len, uint8_t* p_encrypt_data, size_t encrypt_data_len, uint8_t* sealed_blob, uint32_t data_size)
{
	sgx_status_t status;
	ms_seal_data_t ms;
	ms.ms_p_aad_mac_text = p_aad_mac_text;
	ms.ms_aad_mac_text_len = aad_mac_text_len;
	ms.ms_p_encrypt_data = p_encrypt_data;
	ms.ms_encrypt_data_len = encrypt_data_len;
	ms.ms_sealed_blob = sealed_blob;
	ms.ms_data_size = data_size;
	status = sgx_ecall(eid, 1, &ocall_table_Enclave_Seal, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t generate_aes_key_and_seal(sgx_enclave_id_t eid, sgx_status_t* retval, uint8_t* p_aes_key, uint32_t key_size)
{
	sgx_status_t status;
	ms_generate_aes_key_and_seal_t ms;
	ms.ms_p_aes_key = p_aes_key;
	ms.ms_key_size = key_size;
	status = sgx_ecall(eid, 2, &ocall_table_Enclave_Seal, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t generate_rsa_key_and_seal(sgx_enclave_id_t eid, sgx_status_t* retval, unsigned char* p_n, unsigned char* p_d, unsigned char* p_p, unsigned char* p_q, unsigned char* p_dmp1, unsigned char* p_dmq1, unsigned char* p_iqmp)
{
	sgx_status_t status;
	ms_generate_rsa_key_and_seal_t ms;
	ms.ms_p_n = p_n;
	ms.ms_p_d = p_d;
	ms.ms_p_p = p_p;
	ms.ms_p_q = p_q;
	ms.ms_p_dmp1 = p_dmp1;
	ms.ms_p_dmq1 = p_dmq1;
	ms.ms_p_iqmp = p_iqmp;
	status = sgx_ecall(eid, 3, &ocall_table_Enclave_Seal, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t encrypt_by_rsa_pubkey(sgx_enclave_id_t eid, sgx_status_t* retval, unsigned char* p_n, unsigned char* p_data, size_t data_size, unsigned char* p_encrypt_data, size_t encrypt_data_size)
{
	sgx_status_t status;
	ms_encrypt_by_rsa_pubkey_t ms;
	ms.ms_p_n = p_n;
	ms.ms_p_data = p_data;
	ms.ms_data_size = data_size;
	ms.ms_p_encrypt_data = p_encrypt_data;
	ms.ms_encrypt_data_size = encrypt_data_size;
	status = sgx_ecall(eid, 4, &ocall_table_Enclave_Seal, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t get_unsealed_data_size(sgx_enclave_id_t eid, const uint8_t* sealed_blob, size_t data_size, uint32_t* p_mac_text_len, uint32_t* p_decrypt_data_len)
{
	sgx_status_t status;
	ms_get_unsealed_data_size_t ms;
	ms.ms_sealed_blob = sealed_blob;
	ms.ms_data_size = data_size;
	ms.ms_p_mac_text_len = p_mac_text_len;
	ms.ms_p_decrypt_data_len = p_decrypt_data_len;
	status = sgx_ecall(eid, 5, &ocall_table_Enclave_Seal, &ms);
	return status;
}

sgx_status_t unseal_data(sgx_enclave_id_t eid, sgx_status_t* retval, const uint8_t* sealed_blob, size_t data_size, uint8_t* p_mac_text, size_t mac_data_size, uint8_t* p_decrypt_data, size_t decrypt_data_size)
{
	sgx_status_t status;
	ms_unseal_data_t ms;
	ms.ms_sealed_blob = sealed_blob;
	ms.ms_data_size = data_size;
	ms.ms_p_mac_text = p_mac_text;
	ms.ms_mac_data_size = mac_data_size;
	ms.ms_p_decrypt_data = p_decrypt_data;
	ms.ms_decrypt_data_size = decrypt_data_size;
	status = sgx_ecall(eid, 6, &ocall_table_Enclave_Seal, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t decrypt_by_rsa_prikey(sgx_enclave_id_t eid, sgx_status_t* retval, unsigned char* p_p, unsigned char* p_q, unsigned char* p_dmp1, unsigned char* p_dmq1, unsigned char* p_iqmp, uint8_t* p_data, size_t data_size, uint8_t* p_decrypt_data, size_t decrypt_data_size)
{
	sgx_status_t status;
	ms_decrypt_by_rsa_prikey_t ms;
	ms.ms_p_p = p_p;
	ms.ms_p_q = p_q;
	ms.ms_p_dmp1 = p_dmp1;
	ms.ms_p_dmq1 = p_dmq1;
	ms.ms_p_iqmp = p_iqmp;
	ms.ms_p_data = p_data;
	ms.ms_data_size = data_size;
	ms.ms_p_decrypt_data = p_decrypt_data;
	ms.ms_decrypt_data_size = decrypt_data_size;
	status = sgx_ecall(eid, 7, &ocall_table_Enclave_Seal, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t sign_data_with_rsa(sgx_enclave_id_t eid, sgx_status_t* retval, unsigned char* p_n, unsigned char* p_d, uint8_t* p_data, size_t data_len, uint8_t* p_sig)
{
	sgx_status_t status;
	ms_sign_data_with_rsa_t ms;
	ms.ms_p_n = p_n;
	ms.ms_p_d = p_d;
	ms.ms_p_data = p_data;
	ms.ms_data_len = data_len;
	ms.ms_p_sig = p_sig;
	status = sgx_ecall(eid, 8, &ocall_table_Enclave_Seal, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t verify_signature_with_rsa(sgx_enclave_id_t eid, sgx_status_t* retval, unsigned char* p_n, uint8_t* p_data, size_t data_len, uint8_t* p_sig, uint8_t* is_valid)
{
	sgx_status_t status;
	ms_verify_signature_with_rsa_t ms;
	ms.ms_p_n = p_n;
	ms.ms_p_data = p_data;
	ms.ms_data_len = data_len;
	ms.ms_p_sig = p_sig;
	ms.ms_is_valid = is_valid;
	status = sgx_ecall(eid, 9, &ocall_table_Enclave_Seal, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t forge(sgx_enclave_id_t eid, mpz_t* s, mpz_t* q, mpz_t* t, mpz_t* r, mpz_t* t_new, mpz_t* r_new)
{
	sgx_status_t status;
	ms_forge_t ms;
	ms.ms_s = s;
	ms.ms_q = q;
	ms.ms_t = t;
	ms.ms_r = r;
	ms.ms_t_new = t_new;
	ms.ms_r_new = r_new;
	status = sgx_ecall(eid, 10, &ocall_table_Enclave_Seal, &ms);
	return status;
}

sgx_status_t enclave_create_report(sgx_enclave_id_t eid, uint32_t* retval, const sgx_target_info_t* p_qe3_target, sgx_report_t* p_report)
{
	sgx_status_t status;
	ms_enclave_create_report_t ms;
	ms.ms_p_qe3_target = p_qe3_target;
	ms.ms_p_report = p_report;
	status = sgx_ecall(eid, 11, &ocall_table_Enclave_Seal, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_get_target_info(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_target_info_t* target_info)
{
	sgx_status_t status;
	ms_ecall_get_target_info_t ms;
	ms.ms_target_info = target_info;
	status = sgx_ecall(eid, 12, &ocall_table_Enclave_Seal, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t generate_encrypt_and_report(sgx_enclave_id_t eid, bool* retval, sgx_target_info_t* p_qe_target_info, unsigned char* encrypted_p, size_t encrypted_p_len, unsigned char* encrypted_q, size_t encrypted_q_len, unsigned char* encrypted_dmp1, size_t encrypted_dmp1_len, unsigned char* encrypted_dmq1, size_t encrypted_dmq1_len, unsigned char* encrypted_iqmp, size_t encrypted_iqmp_len, sgx_report_t* p_report)
{
	sgx_status_t status;
	ms_generate_encrypt_and_report_t ms;
	ms.ms_p_qe_target_info = p_qe_target_info;
	ms.ms_encrypted_p = encrypted_p;
	ms.ms_encrypted_p_len = encrypted_p_len;
	ms.ms_encrypted_q = encrypted_q;
	ms.ms_encrypted_q_len = encrypted_q_len;
	ms.ms_encrypted_dmp1 = encrypted_dmp1;
	ms.ms_encrypted_dmp1_len = encrypted_dmp1_len;
	ms.ms_encrypted_dmq1 = encrypted_dmq1;
	ms.ms_encrypted_dmq1_len = encrypted_dmq1_len;
	ms.ms_encrypted_iqmp = encrypted_iqmp;
	ms.ms_encrypted_iqmp_len = encrypted_iqmp_len;
	ms.ms_p_report = p_report;
	status = sgx_ecall(eid, 13, &ocall_table_Enclave_Seal, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t sgx_tvl_verify_qve_report_and_identity(sgx_enclave_id_t eid, quote3_error_t* retval, const uint8_t* p_quote, uint32_t quote_size, const sgx_ql_qe_report_info_t* p_qve_report_info, time_t expiration_check_date, uint32_t collateral_expiration_status, sgx_ql_qv_result_t quote_verification_result, const uint8_t* p_supplemental_data, uint32_t supplemental_data_size, sgx_isv_svn_t qve_isvsvn_threshold)
{
	sgx_status_t status;
	ms_sgx_tvl_verify_qve_report_and_identity_t ms;
	ms.ms_p_quote = p_quote;
	ms.ms_quote_size = quote_size;
	ms.ms_p_qve_report_info = p_qve_report_info;
	ms.ms_expiration_check_date = expiration_check_date;
	ms.ms_collateral_expiration_status = collateral_expiration_status;
	ms.ms_quote_verification_result = quote_verification_result;
	ms.ms_p_supplemental_data = p_supplemental_data;
	ms.ms_supplemental_data_size = supplemental_data_size;
	ms.ms_qve_isvsvn_threshold = qve_isvsvn_threshold;
	status = sgx_ecall(eid, 14, &ocall_table_Enclave_Seal, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t tee_verify_qae_report_and_identity(sgx_enclave_id_t eid, quote3_error_t* retval, qae_verification_input_t* input, sgx_ql_qe_report_info_t qae_report_info, sgx_isv_svn_t qae_isvsvn_threshold)
{
	sgx_status_t status;
	ms_tee_verify_qae_report_and_identity_t ms;
	ms.ms_input = input;
	ms.ms_qae_report_info = qae_report_info;
	ms.ms_qae_isvsvn_threshold = qae_isvsvn_threshold;
	status = sgx_ecall(eid, 15, &ocall_table_Enclave_Seal, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

