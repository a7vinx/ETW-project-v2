#include <windows.h>
#include <evntrace.h>
#include <cstdio>
#include <tdh.h> //PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD
#include <dia2.h>

#include "trace_producer.h"


using namespace std;

trace_producer::trace_producer(){
begin:
	event_logfile_header = &event_logfile.LogfileHeader;
	ZeroMemory(&event_logfile, sizeof(EVENT_TRACE_LOGFILE));
	event_logfile.LoggerName = KERNEL_LOGGER_NAME;

	event_logfile.EventRecordCallback = (PEVENT_RECORD_CALLBACK)(consum_event); //produceEvent() is the callback function. should be writed in this class.

	event_logfile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
	event_logfile_handle = OpenTrace(&event_logfile);
	if (INVALID_PROCESSTRACE_HANDLE == event_logfile_handle){
		wprintf(L"OpenTrace failed with %lu\n", GetLastError());
		goto cleanup;
	}

	event_usermode = event_logfile_header->LogFileMode & EVENT_TRACE_PRIVATE_LOGGER_MODE;
	if (event_logfile_header->PointerSize != sizeof(PVOID)){
		event_logfile_header = (PTRACE_LOGFILE_HEADER)((PUCHAR)event_logfile_header +
			2 * (event_logfile_header->PointerSize - sizeof(PVOID)));
	}

	TDHSTATUS temp_status = ProcessTrace(&event_logfile_handle, 1, 0, 0);
	if (temp_status != ERROR_SUCCESS && temp_status != ERROR_CANCELLED){
		wprintf(L"ProcessTrace failed with %lu\n", temp_status);
		goto cleanup;
	}

cleanup:
	if (INVALID_PROCESSTRACE_HANDLE != event_logfile_handle){
		temp_status = CloseTrace(event_logfile_handle);
	}
	goto begin;
}

VOID WINAPI consum_event(PEVENT_RECORD event_pointer){

}