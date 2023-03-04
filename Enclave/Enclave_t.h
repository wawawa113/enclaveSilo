#ifndef ENCLAVE_T_H__
#define ENCLAVE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */

#include "user_types.h"
#include "stdint.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

#ifdef NO_HARDEN_EXT_WRITES
#define MEMCPY_S memcpy_s
#define MEMSET memset
#else
#define MEMCPY_S memcpy_verw_s
#define MEMSET memset_verw
#endif /* NO_HARDEN_EXT_WRITES */

void ecall_initDB(void);
void ecall_worker_th(int thid, int gid);
void ecall_logger_th(int thid);
void ecall_waitForReady(void);
void ecall_sendStart(void);
void ecall_sendQuit(void);
uint64_t ecall_getAbortResult(int thid);
uint64_t ecall_getCommitResult(int thid);
void ecall_showLoggerResult(int thid);
uint64_t ecall_showDurableEpoch(void);

sgx_status_t SGX_CDECL ocall_print_string(const char* str);
sgx_status_t SGX_CDECL ocall_save_logfile(int* retval, int thid, const uint8_t* sealed_data, size_t sealed_size);
sgx_status_t SGX_CDECL ocall_save_pepochfile(int* retval, const uint8_t* sealed_data, size_t sealed_size);
sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter);
sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
