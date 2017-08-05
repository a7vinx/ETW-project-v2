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
};

class trace_producer{
public:
	trace_producer();

	// The function will set up the etw producer and call the call_back function.
	static void setup_event_producer(void);
	// Parse the buffered event.
	//static void parse_event(trace_buffer_format trace);

private:

	static system_information sys_info;

	// Some variable for multi_thread sync.
	//static int producer_position;
	//static int consumer_position;

	// The call_back function, in this case it should parser the pHeader and write important information to the trace_buffer.
	static VOID WINAPI consum_event(PEVENT_RECORD event_pointer); // the callback function for ETW

};

#endif
