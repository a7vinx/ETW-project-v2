#ifndef TRACE_COLLECTER_TRACE_PRODUCER
#define TRACE_COLLECTER_TRACE_PRODUCER

#include <windows.h>
#include <stdio.h>
#include <wbemidl.h>
#include <wmistr.h>
#include <evntrace.h>
#include <tdh.h>
#include <in6addr.h>


using namespace std;

class trace_producer{
public:
	trace_producer();
	
private:
	static VOID WINAPI consum_event(PEVENT_RECORD event_pointer); // the callback function for ETW

};

#endif