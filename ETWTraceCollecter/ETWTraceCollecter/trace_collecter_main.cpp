#include <iostream>
#include <process.h>

#include "system_information.h"
#include "getAddress.h"
#include "etw_configuring.h"
#include "trace_producer.h"


using namespace std;

trace_buffer_format trace_buffer[TRACE_BUFFER_SIZE];
int producer_position = 0;

void wmain(int argc, char* argv[]){
	// Configure the ETW provider, so we can get the event we want and the output way.
	etw_configuring etw;
	if (0 == etw.start_etw()) // There should be etw.stop_etw(). So that the etw can quit.
		wprintf(L"ETW trace session start successfully!\n");
	else{
		wprintf(L"ETW trace session go WRONG! press any key to quit.\n");
		_getch();
		return;
	}

	trace_producer trace;
	trace.setup_event_producer();

	etw.stop_etw();
	wprintf(L"WELL DONE!\n");
	_getch();
}