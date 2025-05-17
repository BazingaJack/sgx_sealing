#include "Enclave_Seal_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */
#include "sgx_lfence.h" /* for sgx_lfence */

#include <errno.h>
#include <mbusafecrt.h> /* for memcpy_s etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_ENCLAVE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_within_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define ADD_ASSIGN_OVERFLOW(a, b) (	\
	((a) += (b)) < (b)	\
)


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

typedef struct ms_ocall_print_string_t {
	const char* ms_str;
} ms_ocall_print_string_t;

typedef struct ms_ocall_print_num_t {
	uint32_t* ms_num;
} ms_ocall_print_num_t;

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

static sgx_status_t SGX_CDECL sgx_get_sealed_data_size(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_get_sealed_data_size_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_get_sealed_data_size_t* ms = SGX_CAST(ms_get_sealed_data_size_t*, pms);
	ms_get_sealed_data_size_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_get_sealed_data_size_t), ms, sizeof(ms_get_sealed_data_size_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	size_t* _tmp_aad_mac_text_len = __in_ms.ms_aad_mac_text_len;
	size_t _len_aad_mac_text_len = sizeof(size_t);
	size_t* _in_aad_mac_text_len = NULL;
	size_t* _tmp_encrypt_data_len = __in_ms.ms_encrypt_data_len;
	size_t _len_encrypt_data_len = sizeof(size_t);
	size_t* _in_encrypt_data_len = NULL;
	uint32_t _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_aad_mac_text_len, _len_aad_mac_text_len);
	CHECK_UNIQUE_POINTER(_tmp_encrypt_data_len, _len_encrypt_data_len);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_aad_mac_text_len != NULL && _len_aad_mac_text_len != 0) {
		if ( _len_aad_mac_text_len % sizeof(*_tmp_aad_mac_text_len) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_aad_mac_text_len = (size_t*)malloc(_len_aad_mac_text_len);
		if (_in_aad_mac_text_len == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_aad_mac_text_len, _len_aad_mac_text_len, _tmp_aad_mac_text_len, _len_aad_mac_text_len)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_encrypt_data_len != NULL && _len_encrypt_data_len != 0) {
		if ( _len_encrypt_data_len % sizeof(*_tmp_encrypt_data_len) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_encrypt_data_len = (size_t*)malloc(_len_encrypt_data_len);
		if (_in_encrypt_data_len == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_encrypt_data_len, _len_encrypt_data_len, _tmp_encrypt_data_len, _len_encrypt_data_len)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	_in_retval = get_sealed_data_size(_in_aad_mac_text_len, _in_encrypt_data_len);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}

err:
	if (_in_aad_mac_text_len) free(_in_aad_mac_text_len);
	if (_in_encrypt_data_len) free(_in_encrypt_data_len);
	return status;
}

static sgx_status_t SGX_CDECL sgx_seal_data(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_seal_data_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_seal_data_t* ms = SGX_CAST(ms_seal_data_t*, pms);
	ms_seal_data_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_seal_data_t), ms, sizeof(ms_seal_data_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_p_aad_mac_text = __in_ms.ms_p_aad_mac_text;
	size_t _tmp_aad_mac_text_len = __in_ms.ms_aad_mac_text_len;
	size_t _len_p_aad_mac_text = _tmp_aad_mac_text_len;
	uint8_t* _in_p_aad_mac_text = NULL;
	uint8_t* _tmp_p_encrypt_data = __in_ms.ms_p_encrypt_data;
	size_t _tmp_encrypt_data_len = __in_ms.ms_encrypt_data_len;
	size_t _len_p_encrypt_data = _tmp_encrypt_data_len;
	uint8_t* _in_p_encrypt_data = NULL;
	uint8_t* _tmp_sealed_blob = __in_ms.ms_sealed_blob;
	uint32_t _tmp_data_size = __in_ms.ms_data_size;
	size_t _len_sealed_blob = _tmp_data_size;
	uint8_t* _in_sealed_blob = NULL;
	sgx_status_t _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_p_aad_mac_text, _len_p_aad_mac_text);
	CHECK_UNIQUE_POINTER(_tmp_p_encrypt_data, _len_p_encrypt_data);
	CHECK_UNIQUE_POINTER(_tmp_sealed_blob, _len_sealed_blob);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_p_aad_mac_text != NULL && _len_p_aad_mac_text != 0) {
		if ( _len_p_aad_mac_text % sizeof(*_tmp_p_aad_mac_text) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_p_aad_mac_text = (uint8_t*)malloc(_len_p_aad_mac_text);
		if (_in_p_aad_mac_text == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_p_aad_mac_text, _len_p_aad_mac_text, _tmp_p_aad_mac_text, _len_p_aad_mac_text)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_p_encrypt_data != NULL && _len_p_encrypt_data != 0) {
		if ( _len_p_encrypt_data % sizeof(*_tmp_p_encrypt_data) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_p_encrypt_data = (uint8_t*)malloc(_len_p_encrypt_data);
		if (_in_p_encrypt_data == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_p_encrypt_data, _len_p_encrypt_data, _tmp_p_encrypt_data, _len_p_encrypt_data)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_sealed_blob != NULL && _len_sealed_blob != 0) {
		if ( _len_sealed_blob % sizeof(*_tmp_sealed_blob) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_sealed_blob = (uint8_t*)malloc(_len_sealed_blob)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_sealed_blob, 0, _len_sealed_blob);
	}
	_in_retval = seal_data(_in_p_aad_mac_text, _tmp_aad_mac_text_len, _in_p_encrypt_data, _tmp_encrypt_data_len, _in_sealed_blob, _tmp_data_size);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}
	if (_in_sealed_blob) {
		if (memcpy_verw_s(_tmp_sealed_blob, _len_sealed_blob, _in_sealed_blob, _len_sealed_blob)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_p_aad_mac_text) free(_in_p_aad_mac_text);
	if (_in_p_encrypt_data) free(_in_p_encrypt_data);
	if (_in_sealed_blob) free(_in_sealed_blob);
	return status;
}

static sgx_status_t SGX_CDECL sgx_generate_aes_key_and_seal(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_generate_aes_key_and_seal_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_generate_aes_key_and_seal_t* ms = SGX_CAST(ms_generate_aes_key_and_seal_t*, pms);
	ms_generate_aes_key_and_seal_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_generate_aes_key_and_seal_t), ms, sizeof(ms_generate_aes_key_and_seal_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_p_aes_key = __in_ms.ms_p_aes_key;
	uint32_t _tmp_key_size = __in_ms.ms_key_size;
	size_t _len_p_aes_key = _tmp_key_size;
	uint8_t* _in_p_aes_key = NULL;
	sgx_status_t _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_p_aes_key, _len_p_aes_key);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_p_aes_key != NULL && _len_p_aes_key != 0) {
		if ( _len_p_aes_key % sizeof(*_tmp_p_aes_key) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_p_aes_key = (uint8_t*)malloc(_len_p_aes_key)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_p_aes_key, 0, _len_p_aes_key);
	}
	_in_retval = generate_aes_key_and_seal(_in_p_aes_key, _tmp_key_size);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}
	if (_in_p_aes_key) {
		if (memcpy_verw_s(_tmp_p_aes_key, _len_p_aes_key, _in_p_aes_key, _len_p_aes_key)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_p_aes_key) free(_in_p_aes_key);
	return status;
}

static sgx_status_t SGX_CDECL sgx_generate_rsa_key_and_seal(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_generate_rsa_key_and_seal_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_generate_rsa_key_and_seal_t* ms = SGX_CAST(ms_generate_rsa_key_and_seal_t*, pms);
	ms_generate_rsa_key_and_seal_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_generate_rsa_key_and_seal_t), ms, sizeof(ms_generate_rsa_key_and_seal_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	unsigned char* _tmp_p_n = __in_ms.ms_p_n;
	size_t _len_p_n = 384;
	unsigned char* _in_p_n = NULL;
	unsigned char* _tmp_p_p = __in_ms.ms_p_p;
	size_t _len_p_p = 192;
	unsigned char* _in_p_p = NULL;
	unsigned char* _tmp_p_q = __in_ms.ms_p_q;
	size_t _len_p_q = 192;
	unsigned char* _in_p_q = NULL;
	unsigned char* _tmp_p_dmp1 = __in_ms.ms_p_dmp1;
	size_t _len_p_dmp1 = 192;
	unsigned char* _in_p_dmp1 = NULL;
	unsigned char* _tmp_p_dmq1 = __in_ms.ms_p_dmq1;
	size_t _len_p_dmq1 = 192;
	unsigned char* _in_p_dmq1 = NULL;
	unsigned char* _tmp_p_iqmp = __in_ms.ms_p_iqmp;
	size_t _len_p_iqmp = 192;
	unsigned char* _in_p_iqmp = NULL;
	sgx_status_t _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_p_n, _len_p_n);
	CHECK_UNIQUE_POINTER(_tmp_p_p, _len_p_p);
	CHECK_UNIQUE_POINTER(_tmp_p_q, _len_p_q);
	CHECK_UNIQUE_POINTER(_tmp_p_dmp1, _len_p_dmp1);
	CHECK_UNIQUE_POINTER(_tmp_p_dmq1, _len_p_dmq1);
	CHECK_UNIQUE_POINTER(_tmp_p_iqmp, _len_p_iqmp);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_p_n != NULL && _len_p_n != 0) {
		if ( _len_p_n % sizeof(*_tmp_p_n) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_p_n = (unsigned char*)malloc(_len_p_n)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_p_n, 0, _len_p_n);
	}
	if (_tmp_p_p != NULL && _len_p_p != 0) {
		if ( _len_p_p % sizeof(*_tmp_p_p) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_p_p = (unsigned char*)malloc(_len_p_p)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_p_p, 0, _len_p_p);
	}
	if (_tmp_p_q != NULL && _len_p_q != 0) {
		if ( _len_p_q % sizeof(*_tmp_p_q) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_p_q = (unsigned char*)malloc(_len_p_q)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_p_q, 0, _len_p_q);
	}
	if (_tmp_p_dmp1 != NULL && _len_p_dmp1 != 0) {
		if ( _len_p_dmp1 % sizeof(*_tmp_p_dmp1) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_p_dmp1 = (unsigned char*)malloc(_len_p_dmp1)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_p_dmp1, 0, _len_p_dmp1);
	}
	if (_tmp_p_dmq1 != NULL && _len_p_dmq1 != 0) {
		if ( _len_p_dmq1 % sizeof(*_tmp_p_dmq1) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_p_dmq1 = (unsigned char*)malloc(_len_p_dmq1)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_p_dmq1, 0, _len_p_dmq1);
	}
	if (_tmp_p_iqmp != NULL && _len_p_iqmp != 0) {
		if ( _len_p_iqmp % sizeof(*_tmp_p_iqmp) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_p_iqmp = (unsigned char*)malloc(_len_p_iqmp)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_p_iqmp, 0, _len_p_iqmp);
	}
	_in_retval = generate_rsa_key_and_seal(_in_p_n, _in_p_p, _in_p_q, _in_p_dmp1, _in_p_dmq1, _in_p_iqmp);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}
	if (_in_p_n) {
		if (memcpy_verw_s(_tmp_p_n, _len_p_n, _in_p_n, _len_p_n)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_p_p) {
		if (memcpy_verw_s(_tmp_p_p, _len_p_p, _in_p_p, _len_p_p)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_p_q) {
		if (memcpy_verw_s(_tmp_p_q, _len_p_q, _in_p_q, _len_p_q)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_p_dmp1) {
		if (memcpy_verw_s(_tmp_p_dmp1, _len_p_dmp1, _in_p_dmp1, _len_p_dmp1)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_p_dmq1) {
		if (memcpy_verw_s(_tmp_p_dmq1, _len_p_dmq1, _in_p_dmq1, _len_p_dmq1)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_p_iqmp) {
		if (memcpy_verw_s(_tmp_p_iqmp, _len_p_iqmp, _in_p_iqmp, _len_p_iqmp)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_p_n) free(_in_p_n);
	if (_in_p_p) free(_in_p_p);
	if (_in_p_q) free(_in_p_q);
	if (_in_p_dmp1) free(_in_p_dmp1);
	if (_in_p_dmq1) free(_in_p_dmq1);
	if (_in_p_iqmp) free(_in_p_iqmp);
	return status;
}

static sgx_status_t SGX_CDECL sgx_encrypt_by_rsa_pubkey(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_encrypt_by_rsa_pubkey_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_encrypt_by_rsa_pubkey_t* ms = SGX_CAST(ms_encrypt_by_rsa_pubkey_t*, pms);
	ms_encrypt_by_rsa_pubkey_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_encrypt_by_rsa_pubkey_t), ms, sizeof(ms_encrypt_by_rsa_pubkey_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	unsigned char* _tmp_p_n = __in_ms.ms_p_n;
	size_t _len_p_n = 384;
	unsigned char* _in_p_n = NULL;
	unsigned char* _tmp_p_data = __in_ms.ms_p_data;
	size_t _tmp_data_size = __in_ms.ms_data_size;
	size_t _len_p_data = _tmp_data_size;
	unsigned char* _in_p_data = NULL;
	unsigned char* _tmp_p_encrypt_data = __in_ms.ms_p_encrypt_data;
	size_t _tmp_encrypt_data_size = __in_ms.ms_encrypt_data_size;
	size_t _len_p_encrypt_data = _tmp_encrypt_data_size;
	unsigned char* _in_p_encrypt_data = NULL;
	sgx_status_t _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_p_n, _len_p_n);
	CHECK_UNIQUE_POINTER(_tmp_p_data, _len_p_data);
	CHECK_UNIQUE_POINTER(_tmp_p_encrypt_data, _len_p_encrypt_data);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_p_n != NULL && _len_p_n != 0) {
		if ( _len_p_n % sizeof(*_tmp_p_n) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_p_n = (unsigned char*)malloc(_len_p_n);
		if (_in_p_n == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_p_n, _len_p_n, _tmp_p_n, _len_p_n)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_p_data != NULL && _len_p_data != 0) {
		if ( _len_p_data % sizeof(*_tmp_p_data) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_p_data = (unsigned char*)malloc(_len_p_data);
		if (_in_p_data == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_p_data, _len_p_data, _tmp_p_data, _len_p_data)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_p_encrypt_data != NULL && _len_p_encrypt_data != 0) {
		if ( _len_p_encrypt_data % sizeof(*_tmp_p_encrypt_data) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_p_encrypt_data = (unsigned char*)malloc(_len_p_encrypt_data)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_p_encrypt_data, 0, _len_p_encrypt_data);
	}
	_in_retval = encrypt_by_rsa_pubkey(_in_p_n, _in_p_data, _tmp_data_size, _in_p_encrypt_data, _tmp_encrypt_data_size);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}
	if (_in_p_encrypt_data) {
		if (memcpy_verw_s(_tmp_p_encrypt_data, _len_p_encrypt_data, _in_p_encrypt_data, _len_p_encrypt_data)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_p_n) free(_in_p_n);
	if (_in_p_data) free(_in_p_data);
	if (_in_p_encrypt_data) free(_in_p_encrypt_data);
	return status;
}

static sgx_status_t SGX_CDECL sgx_get_unsealed_data_size(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_get_unsealed_data_size_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_get_unsealed_data_size_t* ms = SGX_CAST(ms_get_unsealed_data_size_t*, pms);
	ms_get_unsealed_data_size_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_get_unsealed_data_size_t), ms, sizeof(ms_get_unsealed_data_size_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	const uint8_t* _tmp_sealed_blob = __in_ms.ms_sealed_blob;
	size_t _tmp_data_size = __in_ms.ms_data_size;
	size_t _len_sealed_blob = _tmp_data_size;
	uint8_t* _in_sealed_blob = NULL;
	uint32_t* _tmp_p_mac_text_len = __in_ms.ms_p_mac_text_len;
	size_t _len_p_mac_text_len = sizeof(uint32_t);
	uint32_t* _in_p_mac_text_len = NULL;
	uint32_t* _tmp_p_decrypt_data_len = __in_ms.ms_p_decrypt_data_len;
	size_t _len_p_decrypt_data_len = sizeof(uint32_t);
	uint32_t* _in_p_decrypt_data_len = NULL;

	CHECK_UNIQUE_POINTER(_tmp_sealed_blob, _len_sealed_blob);
	CHECK_UNIQUE_POINTER(_tmp_p_mac_text_len, _len_p_mac_text_len);
	CHECK_UNIQUE_POINTER(_tmp_p_decrypt_data_len, _len_p_decrypt_data_len);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_sealed_blob != NULL && _len_sealed_blob != 0) {
		if ( _len_sealed_blob % sizeof(*_tmp_sealed_blob) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_sealed_blob = (uint8_t*)malloc(_len_sealed_blob);
		if (_in_sealed_blob == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_sealed_blob, _len_sealed_blob, _tmp_sealed_blob, _len_sealed_blob)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_p_mac_text_len != NULL && _len_p_mac_text_len != 0) {
		if ( _len_p_mac_text_len % sizeof(*_tmp_p_mac_text_len) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_p_mac_text_len = (uint32_t*)malloc(_len_p_mac_text_len)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_p_mac_text_len, 0, _len_p_mac_text_len);
	}
	if (_tmp_p_decrypt_data_len != NULL && _len_p_decrypt_data_len != 0) {
		if ( _len_p_decrypt_data_len % sizeof(*_tmp_p_decrypt_data_len) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_p_decrypt_data_len = (uint32_t*)malloc(_len_p_decrypt_data_len)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_p_decrypt_data_len, 0, _len_p_decrypt_data_len);
	}
	get_unsealed_data_size((const uint8_t*)_in_sealed_blob, _tmp_data_size, _in_p_mac_text_len, _in_p_decrypt_data_len);
	if (_in_p_mac_text_len) {
		if (memcpy_verw_s(_tmp_p_mac_text_len, _len_p_mac_text_len, _in_p_mac_text_len, _len_p_mac_text_len)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_p_decrypt_data_len) {
		if (memcpy_verw_s(_tmp_p_decrypt_data_len, _len_p_decrypt_data_len, _in_p_decrypt_data_len, _len_p_decrypt_data_len)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_sealed_blob) free(_in_sealed_blob);
	if (_in_p_mac_text_len) free(_in_p_mac_text_len);
	if (_in_p_decrypt_data_len) free(_in_p_decrypt_data_len);
	return status;
}

static sgx_status_t SGX_CDECL sgx_unseal_data(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_unseal_data_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_unseal_data_t* ms = SGX_CAST(ms_unseal_data_t*, pms);
	ms_unseal_data_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_unseal_data_t), ms, sizeof(ms_unseal_data_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	const uint8_t* _tmp_sealed_blob = __in_ms.ms_sealed_blob;
	size_t _tmp_data_size = __in_ms.ms_data_size;
	size_t _len_sealed_blob = _tmp_data_size;
	uint8_t* _in_sealed_blob = NULL;
	uint8_t* _tmp_p_mac_text = __in_ms.ms_p_mac_text;
	size_t _tmp_mac_data_size = __in_ms.ms_mac_data_size;
	size_t _len_p_mac_text = _tmp_mac_data_size;
	uint8_t* _in_p_mac_text = NULL;
	uint8_t* _tmp_p_decrypt_data = __in_ms.ms_p_decrypt_data;
	size_t _tmp_decrypt_data_size = __in_ms.ms_decrypt_data_size;
	size_t _len_p_decrypt_data = _tmp_decrypt_data_size;
	uint8_t* _in_p_decrypt_data = NULL;
	sgx_status_t _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_sealed_blob, _len_sealed_blob);
	CHECK_UNIQUE_POINTER(_tmp_p_mac_text, _len_p_mac_text);
	CHECK_UNIQUE_POINTER(_tmp_p_decrypt_data, _len_p_decrypt_data);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_sealed_blob != NULL && _len_sealed_blob != 0) {
		if ( _len_sealed_blob % sizeof(*_tmp_sealed_blob) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_sealed_blob = (uint8_t*)malloc(_len_sealed_blob);
		if (_in_sealed_blob == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_sealed_blob, _len_sealed_blob, _tmp_sealed_blob, _len_sealed_blob)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_p_mac_text != NULL && _len_p_mac_text != 0) {
		if ( _len_p_mac_text % sizeof(*_tmp_p_mac_text) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_p_mac_text = (uint8_t*)malloc(_len_p_mac_text)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_p_mac_text, 0, _len_p_mac_text);
	}
	if (_tmp_p_decrypt_data != NULL && _len_p_decrypt_data != 0) {
		if ( _len_p_decrypt_data % sizeof(*_tmp_p_decrypt_data) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_p_decrypt_data = (uint8_t*)malloc(_len_p_decrypt_data)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_p_decrypt_data, 0, _len_p_decrypt_data);
	}
	_in_retval = unseal_data((const uint8_t*)_in_sealed_blob, _tmp_data_size, _in_p_mac_text, _tmp_mac_data_size, _in_p_decrypt_data, _tmp_decrypt_data_size);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}
	if (_in_p_mac_text) {
		if (memcpy_verw_s(_tmp_p_mac_text, _len_p_mac_text, _in_p_mac_text, _len_p_mac_text)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_p_decrypt_data) {
		if (memcpy_verw_s(_tmp_p_decrypt_data, _len_p_decrypt_data, _in_p_decrypt_data, _len_p_decrypt_data)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_sealed_blob) free(_in_sealed_blob);
	if (_in_p_mac_text) free(_in_p_mac_text);
	if (_in_p_decrypt_data) free(_in_p_decrypt_data);
	return status;
}

static sgx_status_t SGX_CDECL sgx_decrypt_by_rsa_prikey(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_decrypt_by_rsa_prikey_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_decrypt_by_rsa_prikey_t* ms = SGX_CAST(ms_decrypt_by_rsa_prikey_t*, pms);
	ms_decrypt_by_rsa_prikey_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_decrypt_by_rsa_prikey_t), ms, sizeof(ms_decrypt_by_rsa_prikey_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	unsigned char* _tmp_p_p = __in_ms.ms_p_p;
	size_t _len_p_p = 192;
	unsigned char* _in_p_p = NULL;
	unsigned char* _tmp_p_q = __in_ms.ms_p_q;
	size_t _len_p_q = 192;
	unsigned char* _in_p_q = NULL;
	unsigned char* _tmp_p_dmp1 = __in_ms.ms_p_dmp1;
	size_t _len_p_dmp1 = 192;
	unsigned char* _in_p_dmp1 = NULL;
	unsigned char* _tmp_p_dmq1 = __in_ms.ms_p_dmq1;
	size_t _len_p_dmq1 = 192;
	unsigned char* _in_p_dmq1 = NULL;
	unsigned char* _tmp_p_iqmp = __in_ms.ms_p_iqmp;
	size_t _len_p_iqmp = 192;
	unsigned char* _in_p_iqmp = NULL;
	uint8_t* _tmp_p_data = __in_ms.ms_p_data;
	size_t _tmp_data_size = __in_ms.ms_data_size;
	size_t _len_p_data = _tmp_data_size;
	uint8_t* _in_p_data = NULL;
	uint8_t* _tmp_p_decrypt_data = __in_ms.ms_p_decrypt_data;
	size_t _tmp_decrypt_data_size = __in_ms.ms_decrypt_data_size;
	size_t _len_p_decrypt_data = _tmp_decrypt_data_size;
	uint8_t* _in_p_decrypt_data = NULL;
	sgx_status_t _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_p_p, _len_p_p);
	CHECK_UNIQUE_POINTER(_tmp_p_q, _len_p_q);
	CHECK_UNIQUE_POINTER(_tmp_p_dmp1, _len_p_dmp1);
	CHECK_UNIQUE_POINTER(_tmp_p_dmq1, _len_p_dmq1);
	CHECK_UNIQUE_POINTER(_tmp_p_iqmp, _len_p_iqmp);
	CHECK_UNIQUE_POINTER(_tmp_p_data, _len_p_data);
	CHECK_UNIQUE_POINTER(_tmp_p_decrypt_data, _len_p_decrypt_data);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_p_p != NULL && _len_p_p != 0) {
		if ( _len_p_p % sizeof(*_tmp_p_p) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_p_p = (unsigned char*)malloc(_len_p_p);
		if (_in_p_p == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_p_p, _len_p_p, _tmp_p_p, _len_p_p)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_p_q != NULL && _len_p_q != 0) {
		if ( _len_p_q % sizeof(*_tmp_p_q) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_p_q = (unsigned char*)malloc(_len_p_q);
		if (_in_p_q == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_p_q, _len_p_q, _tmp_p_q, _len_p_q)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_p_dmp1 != NULL && _len_p_dmp1 != 0) {
		if ( _len_p_dmp1 % sizeof(*_tmp_p_dmp1) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_p_dmp1 = (unsigned char*)malloc(_len_p_dmp1);
		if (_in_p_dmp1 == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_p_dmp1, _len_p_dmp1, _tmp_p_dmp1, _len_p_dmp1)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_p_dmq1 != NULL && _len_p_dmq1 != 0) {
		if ( _len_p_dmq1 % sizeof(*_tmp_p_dmq1) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_p_dmq1 = (unsigned char*)malloc(_len_p_dmq1);
		if (_in_p_dmq1 == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_p_dmq1, _len_p_dmq1, _tmp_p_dmq1, _len_p_dmq1)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_p_iqmp != NULL && _len_p_iqmp != 0) {
		if ( _len_p_iqmp % sizeof(*_tmp_p_iqmp) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_p_iqmp = (unsigned char*)malloc(_len_p_iqmp);
		if (_in_p_iqmp == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_p_iqmp, _len_p_iqmp, _tmp_p_iqmp, _len_p_iqmp)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_p_data != NULL && _len_p_data != 0) {
		if ( _len_p_data % sizeof(*_tmp_p_data) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_p_data = (uint8_t*)malloc(_len_p_data);
		if (_in_p_data == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_p_data, _len_p_data, _tmp_p_data, _len_p_data)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_p_decrypt_data != NULL && _len_p_decrypt_data != 0) {
		if ( _len_p_decrypt_data % sizeof(*_tmp_p_decrypt_data) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_p_decrypt_data = (uint8_t*)malloc(_len_p_decrypt_data)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_p_decrypt_data, 0, _len_p_decrypt_data);
	}
	_in_retval = decrypt_by_rsa_prikey(_in_p_p, _in_p_q, _in_p_dmp1, _in_p_dmq1, _in_p_iqmp, _in_p_data, _tmp_data_size, _in_p_decrypt_data, _tmp_decrypt_data_size);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}
	if (_in_p_decrypt_data) {
		if (memcpy_verw_s(_tmp_p_decrypt_data, _len_p_decrypt_data, _in_p_decrypt_data, _len_p_decrypt_data)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_p_p) free(_in_p_p);
	if (_in_p_q) free(_in_p_q);
	if (_in_p_dmp1) free(_in_p_dmp1);
	if (_in_p_dmq1) free(_in_p_dmq1);
	if (_in_p_iqmp) free(_in_p_iqmp);
	if (_in_p_data) free(_in_p_data);
	if (_in_p_decrypt_data) free(_in_p_decrypt_data);
	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv; uint8_t is_switchless;} ecall_table[8];
} g_ecall_table = {
	8,
	{
		{(void*)(uintptr_t)sgx_get_sealed_data_size, 0, 0},
		{(void*)(uintptr_t)sgx_seal_data, 0, 0},
		{(void*)(uintptr_t)sgx_generate_aes_key_and_seal, 0, 0},
		{(void*)(uintptr_t)sgx_generate_rsa_key_and_seal, 0, 0},
		{(void*)(uintptr_t)sgx_encrypt_by_rsa_pubkey, 0, 0},
		{(void*)(uintptr_t)sgx_get_unsealed_data_size, 0, 0},
		{(void*)(uintptr_t)sgx_unseal_data, 0, 0},
		{(void*)(uintptr_t)sgx_decrypt_by_rsa_prikey, 0, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[7][8];
} g_dyn_entry_table = {
	7,
	{
		{0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, },
	}
};


sgx_status_t SGX_CDECL ocall_print_string(const char* str)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_str = str ? strlen(str) + 1 : 0;

	ms_ocall_print_string_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_print_string_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(str, _len_str);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (str != NULL) ? _len_str : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_print_string_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_print_string_t));
	ocalloc_size -= sizeof(ms_ocall_print_string_t);

	if (str != NULL) {
		if (memcpy_verw_s(&ms->ms_str, sizeof(const char*), &__tmp, sizeof(const char*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_str % sizeof(*str) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, str, _len_str)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_str);
		ocalloc_size -= _len_str;
	} else {
		ms->ms_str = NULL;
	}

	status = sgx_ocall(0, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_print_num(uint32_t* num)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_num = sizeof(uint32_t);

	ms_ocall_print_num_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_print_num_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(num, _len_num);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (num != NULL) ? _len_num : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_print_num_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_print_num_t));
	ocalloc_size -= sizeof(ms_ocall_print_num_t);

	if (num != NULL) {
		if (memcpy_verw_s(&ms->ms_num, sizeof(uint32_t*), &__tmp, sizeof(uint32_t*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_num % sizeof(*num) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, num, _len_num)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_num);
		ocalloc_size -= _len_num;
	} else {
		ms->ms_num = NULL;
	}

	status = sgx_ocall(1, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_cpuinfo = 4 * sizeof(int);

	ms_sgx_oc_cpuidex_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_oc_cpuidex_t);
	void *__tmp = NULL;

	void *__tmp_cpuinfo = NULL;

	CHECK_ENCLAVE_POINTER(cpuinfo, _len_cpuinfo);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (cpuinfo != NULL) ? _len_cpuinfo : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_oc_cpuidex_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_oc_cpuidex_t));
	ocalloc_size -= sizeof(ms_sgx_oc_cpuidex_t);

	if (cpuinfo != NULL) {
		if (memcpy_verw_s(&ms->ms_cpuinfo, sizeof(int*), &__tmp, sizeof(int*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_cpuinfo = __tmp;
		if (_len_cpuinfo % sizeof(*cpuinfo) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_cpuinfo, 0, _len_cpuinfo);
		__tmp = (void *)((size_t)__tmp + _len_cpuinfo);
		ocalloc_size -= _len_cpuinfo;
	} else {
		ms->ms_cpuinfo = NULL;
	}

	if (memcpy_verw_s(&ms->ms_leaf, sizeof(ms->ms_leaf), &leaf, sizeof(leaf))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_subleaf, sizeof(ms->ms_subleaf), &subleaf, sizeof(subleaf))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(2, ms);

	if (status == SGX_SUCCESS) {
		if (cpuinfo) {
			if (memcpy_s((void*)cpuinfo, _len_cpuinfo, __tmp_cpuinfo, _len_cpuinfo)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_wait_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t);

	if (memcpy_verw_s(&ms->ms_self, sizeof(ms->ms_self), &self, sizeof(self))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(3, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_set_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_untrusted_event_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_set_untrusted_event_ocall_t);

	if (memcpy_verw_s(&ms->ms_waiter, sizeof(ms->ms_waiter), &waiter, sizeof(waiter))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(4, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_setwait_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t);

	if (memcpy_verw_s(&ms->ms_waiter, sizeof(ms->ms_waiter), &waiter, sizeof(waiter))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_self, sizeof(ms->ms_self), &self, sizeof(self))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(5, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_waiters = total * sizeof(void*);

	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(waiters, _len_waiters);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (waiters != NULL) ? _len_waiters : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_multiple_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t);

	if (waiters != NULL) {
		if (memcpy_verw_s(&ms->ms_waiters, sizeof(const void**), &__tmp, sizeof(const void**))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_waiters % sizeof(*waiters) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, waiters, _len_waiters)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_waiters);
		ocalloc_size -= _len_waiters;
	} else {
		ms->ms_waiters = NULL;
	}

	if (memcpy_verw_s(&ms->ms_total, sizeof(ms->ms_total), &total, sizeof(total))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(6, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

