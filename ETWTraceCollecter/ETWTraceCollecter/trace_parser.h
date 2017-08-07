#ifndef TRACE_COLLECTER_TRACE_PRODUCER
#define TRACE_COLLECTER_TRACE_PRODUCER

#include <windows.h>
#include <stdio.h>
#include <wbemidl.h>
#include <wmistr.h>
#include <evntrace.h>
#include <tdh.h>
#include <in6addr.h>

#include "system_information.h"
#include "getAddress.h"

#define TRACE_BUFFER_SIZE 100

using namespace std;

struct trace_buffer_format{
	PVOID user_data;
	//USHORT user_data_size;
	EVENT_HEADER event_hander;
	ETW_BUFFER_CONTEXT buffer_context;
};

struct output_format{
	int cpid;
	DWORD event_type;
};

class trace_parser{
public:
	trace_parser();

	// Parse the buffered event.
	static output_format parse_event(trace_buffer_format trace);

private:
	static system_information sys_info;
	static getAddress syscall_addr;

};



#endif
