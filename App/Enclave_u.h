#ifndef ENCLAVE_U_H__
#define ENCLAVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_status_t etc. */

#include "user_types.h"
#include "stdint.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

#ifndef OCALL_PRINT_STRING_DEFINED__
#define OCALL_PRINT_STRING_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_print_string, (const char* str));
#endif
#ifndef OCALL_SAVE_LOGFILE_DEFINED__
#define OCALL_SAVE_LOGFILE_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_save_logfile, (int thid, const uint8_t* sealed_data, size_t sealed_size));
#endif
#ifndef OCALL_SAVE_PEPOCHFILE_DEFINED__
#define OCALL_SAVE_PEPOCHFILE_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_save_pepochfile, (const uint8_t* sealed_data, size_t sealed_size));
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

sgx_status_t ecall_initDB(sgx_enclave_id_t eid);
sgx_status_t ecall_worker_th(sgx_enclave_id_t eid, int thid, int gid);
sgx_status_t ecall_logger_th(sgx_enclave_id_t eid, int thid);
sgx_status_t ecall_waitForReady(sgx_enclave_id_t eid);
sgx_status_t ecall_sendStart(sgx_enclave_id_t eid);
sgx_status_t ecall_sendQuit(sgx_enclave_id_t eid);
sgx_status_t ecall_getAbortResult(sgx_enclave_id_t eid, uint64_t* retval, int thid);
sgx_status_t ecall_getCommitResult(sgx_enclave_id_t eid, uint64_t* retval, int thid);
sgx_status_t ecall_showLoggerResult(sgx_enclave_id_t eid, int thid);
sgx_status_t ecall_showDurableEpoch(sgx_enclave_id_t eid, uint64_t* retval);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
