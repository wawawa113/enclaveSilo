#include "Enclave_u.h"
#include <errno.h>

typedef struct ms_ecall_worker_th_t {
	int ms_thid;
	int ms_gid;
} ms_ecall_worker_th_t;

typedef struct ms_ecall_logger_th_t {
	int ms_thid;
} ms_ecall_logger_th_t;

typedef struct ms_ecall_getAbortResult_t {
	uint64_t ms_retval;
	int ms_thid;
} ms_ecall_getAbortResult_t;

typedef struct ms_ecall_getCommitResult_t {
	uint64_t ms_retval;
	int ms_thid;
} ms_ecall_getCommitResult_t;

typedef struct ms_ecall_showLoggerResult_t {
	int ms_thid;
} ms_ecall_showLoggerResult_t;

typedef struct ms_ecall_showDurableEpoch_t {
	uint64_t ms_retval;
} ms_ecall_showDurableEpoch_t;

typedef struct ms_ocall_print_string_t {
	const char* ms_str;
} ms_ocall_print_string_t;

typedef struct ms_ocall_save_logfile_t {
	int ms_retval;
	int ms_thid;
	const uint8_t* ms_sealed_data;
	size_t ms_sealed_size;
} ms_ocall_save_logfile_t;

typedef struct ms_ocall_save_pepochfile_t {
	int ms_retval;
	const uint8_t* ms_sealed_data;
	size_t ms_sealed_size;
} ms_ocall_save_pepochfile_t;

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

static sgx_status_t SGX_CDECL Enclave_ocall_print_string(void* pms)
{
	ms_ocall_print_string_t* ms = SGX_CAST(ms_ocall_print_string_t*, pms);
	ocall_print_string(ms->ms_str);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_save_logfile(void* pms)
{
	ms_ocall_save_logfile_t* ms = SGX_CAST(ms_ocall_save_logfile_t*, pms);
	ms->ms_retval = ocall_save_logfile(ms->ms_thid, ms->ms_sealed_data, ms->ms_sealed_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_save_pepochfile(void* pms)
{
	ms_ocall_save_pepochfile_t* ms = SGX_CAST(ms_ocall_save_pepochfile_t*, pms);
	ms->ms_retval = ocall_save_pepochfile(ms->ms_sealed_data, ms->ms_sealed_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_wait_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_wait_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_wait_untrusted_event_ocall(ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_set_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_set_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_untrusted_event_ocall(ms->ms_waiter);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_setwait_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_setwait_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_setwait_untrusted_events_ocall(ms->ms_waiter, ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_set_multiple_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_multiple_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_multiple_untrusted_events_ocall(ms->ms_waiters, ms->ms_total);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[7];
} ocall_table_Enclave = {
	7,
	{
		(void*)Enclave_ocall_print_string,
		(void*)Enclave_ocall_save_logfile,
		(void*)Enclave_ocall_save_pepochfile,
		(void*)Enclave_sgx_thread_wait_untrusted_event_ocall,
		(void*)Enclave_sgx_thread_set_untrusted_event_ocall,
		(void*)Enclave_sgx_thread_setwait_untrusted_events_ocall,
		(void*)Enclave_sgx_thread_set_multiple_untrusted_events_ocall,
	}
};
sgx_status_t ecall_initDB(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 0, &ocall_table_Enclave, NULL);
	return status;
}

sgx_status_t ecall_worker_th(sgx_enclave_id_t eid, int thid, int gid)
{
	sgx_status_t status;
	ms_ecall_worker_th_t ms;
	ms.ms_thid = thid;
	ms.ms_gid = gid;
	status = sgx_ecall(eid, 1, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_logger_th(sgx_enclave_id_t eid, int thid)
{
	sgx_status_t status;
	ms_ecall_logger_th_t ms;
	ms.ms_thid = thid;
	status = sgx_ecall(eid, 2, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_waitForReady(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 3, &ocall_table_Enclave, NULL);
	return status;
}

sgx_status_t ecall_sendStart(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 4, &ocall_table_Enclave, NULL);
	return status;
}

sgx_status_t ecall_sendQuit(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 5, &ocall_table_Enclave, NULL);
	return status;
}

sgx_status_t ecall_getAbortResult(sgx_enclave_id_t eid, uint64_t* retval, int thid)
{
	sgx_status_t status;
	ms_ecall_getAbortResult_t ms;
	ms.ms_thid = thid;
	status = sgx_ecall(eid, 6, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_getCommitResult(sgx_enclave_id_t eid, uint64_t* retval, int thid)
{
	sgx_status_t status;
	ms_ecall_getCommitResult_t ms;
	ms.ms_thid = thid;
	status = sgx_ecall(eid, 7, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_showLoggerResult(sgx_enclave_id_t eid, int thid)
{
	sgx_status_t status;
	ms_ecall_showLoggerResult_t ms;
	ms.ms_thid = thid;
	status = sgx_ecall(eid, 8, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_showDurableEpoch(sgx_enclave_id_t eid, uint64_t* retval)
{
	sgx_status_t status;
	ms_ecall_showDurableEpoch_t ms;
	status = sgx_ecall(eid, 9, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

