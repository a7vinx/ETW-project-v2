#ifndef TRACE_COLLECTER_TRACE_PRODUCER
#define TRACE_COLLECTER_TRACE_PRODUCER

#include <Windows.h>
#include <evntrace.h>


class trace_producer{
public:
	trace_producer();
	
private:
	EVENT_TRACE_LOGFILE event_logfile;
	TRACE_LOGFILE_HEADER* event_logfile_header;
	TRACEHANDLE event_logfile_handle;
	BOOL event_usermode = FALSE;

};

VOID WINAPI consum_event(PEVENT_RECORD event_pointer); // the callback function for ETW

#endif