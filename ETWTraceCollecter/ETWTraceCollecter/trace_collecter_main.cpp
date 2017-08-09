#include <iostream>
#include <process.h>
#include <windows.h>
#include <stdio.h>
#include <wbemidl.h>
#include <wmistr.h>
#include <evntrace.h>
#include <tdh.h> //PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD
#include <in6addr.h>
#include <dia2.h>
#include <mutex>
#include <condition_variable>
#include <signal.h>

#include "system_information.h"
#include "getAddress.h"
#include "etw_configuring.h"
#include "trace_parser.h"
#include "trace_collecter_main.h"


using namespace std;

// For trace buffer's multithread safety.
trace_buffer_format trace_buffer[TRACE_BUFFER_SIZE];
mutex trace_buffer_mutex;
condition_variable trace_not_full_cv;
condition_variable trace_not_empty_cv;
int trace_buffer_size = 0;
int producer_position = 0;
int consumer_position = 0;
int producer_counter = 0;
int consumer_counter = 0;

output_format output_buffer[OUTPUT_SIZE];
int output_position = 0;

trace_parser parser;
etw_configuring etw;

HANDLE parser_thread_handle;
HANDLE consumer_thread_handle;


void wmain(int argc, char* argv[]){
	// Configure the ETW provider, so we can get the event we want and the output way.
	if (0 == etw.start_etw()) // There should be etw.stop_etw(). So that the etw can quit.
		wprintf(L"ETW trace session start successfully!\n");
	else{
		wprintf(L"ETW trace session go WRONG! press any key to quit.\n");
		_getch();
		return;
	}

	signal(SIGINT, exit_etw);

	consumer_thread_handle = (HANDLE)_beginthread(setup_event_producer, 0, NULL);
	//parser_thread_handle = (HANDLE)_beginthread(parse_event_multi_thread, 0, NULL);
	//_beginthread(parse_event_multi_thread, 0, NULL);
	//_beginthread(parse_event_multi_thread, 0, NULL);
	//_beginthread(parse_event_multi_thread, 0, NULL);
	
	/*try{
		setup_event_producer(NULL);
	}
	catch (...){
		wprintf(L"haaaaaa\n");;
	}*/

	while (1){
		Sleep(100000);
	}
}

void exit_etw(int signal_num){
	etw.stop_etw();
	wprintf(L"ETW stop successful!\n");
	CloseHandle(consumer_thread_handle);
	wprintf(L"consumer stop successful!\n");
	exit(0);
}

// The function will set up the etw producer and call the call_back function.
VOID __cdecl setup_event_producer(void*){
	EVENT_TRACE_LOGFILE event_logfile;
	TRACE_LOGFILE_HEADER* event_logfile_header;
	TRACEHANDLE event_logfile_handle;
	BOOL event_usermode = FALSE;

begin:
	event_logfile_header = &event_logfile.LogfileHeader;
	ZeroMemory(&event_logfile, sizeof(EVENT_TRACE_LOGFILE));
	event_logfile.LoggerName = KERNEL_LOGGER_NAME;

	// consum_event() is the callback function. should be writed in this class.
	// If everything go well, the program will be block here.
	event_logfile.EventRecordCallback = (PEVENT_RECORD_CALLBACK)(consum_event);

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

// The call_back function, in this case it should parser the pHeader and write important information to the trace_buffer.
VOID WINAPI consum_event(PEVENT_RECORD event_pointer){
	//Sleep(1);
	//unique_lock<mutex> lock(trace_buffer_mutex);

	//trace_not_full_cv.wait(lock, [=] {return trace_buffer_size < TRACE_BUFFER_SIZE; });

	{
		//// This function can't use member variables.
		//trace_buffer_format trace_buffer[TRACE_BUFFER_SIZE];
		//int producer_position;
		trace_buffer_format temp_trace;
		//pEventBuffer[producterPos] = pEvent;
		temp_trace.user_data = event_pointer->UserData;
		//trace_buffer[producer_position].user_data_size = event_pointer->UserDataLength;
		temp_trace.buffer_context = event_pointer->BufferContext;
		temp_trace.event_header = event_pointer->EventHeader;

		// temp
		{
			output_format temp_output = parser.parse_event(temp_trace);
			if (temp_output.event_type != 0){
				output_buffer[output_position] = temp_output;
				output_position = (output_position + 1) % OUTPUT_SIZE;
			}
		}

		//trace_buffer[producer_position] = temp_trace;

		////cout << (event_pointer->EventHeader).Size << "+" << event_pointer->UserDataLength << "=" << (event_pointer->EventHeader).Size + event_pointer->UserDataLength << "?=" << event_pointer->UserData;

		//producer_position = (producer_position + 1) % TRACE_BUFFER_SIZE;
		//++trace_buffer_size;
		++producer_counter;
		//wprintf(L"Producer_position:%d\tTrace_buffer_size:%d\n", producer_position, trace_buffer_size);
	}

	//lock.unlock();

	//trace_not_empty_cv.notify_all();
	////notEmptyCv.notify_all();
}

VOID __cdecl parse_event_multi_thread(void*){
	while (1)
	{
		unique_lock<mutex> lock(trace_buffer_mutex);
		trace_not_empty_cv.wait(lock, [=] {return trace_buffer_size > 0; });

		output_format output;
		output = parser.parse_event(trace_buffer[consumer_position]);
		consumer_position = (consumer_position + 1) % TRACE_BUFFER_SIZE;
		--trace_buffer_size;
		++consumer_counter;
		//wprintf(L"Consumer_position:%d\tTrace_buffer_size:%d\n", consumer_position, trace_buffer_size);

		lock.unlock();
		trace_not_full_cv.notify_one();

		if (output.event_type != 0){
			output_buffer[output_position] = output;
			output_position = (output_position + 1) % OUTPUT_SIZE;
		}
	}
}