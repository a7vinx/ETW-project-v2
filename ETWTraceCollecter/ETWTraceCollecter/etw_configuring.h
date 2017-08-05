#ifndef TRACE_COLLECTER_ETW_CONFIGURING
#define TRACE_COLLECTER_ETW_CONFIGURING

#include <windows.h>
#include <conio.h>
#include <strsafe.h>
#include <wmistr.h>
#include <evntrace.h>


#define LOGFILE_PATH L"C:\\Users\\admin\\Desktop\\ETW-project-v2\\ETWTraceCollecter\\ETWTraceCollecter\\res\\IMAGE_LOAD2.etl"

using namespace std;

class etw_configuring{
public:
	int start_etw(void);
	void stop_etw(void);

private:
	TRACEHANDLE SessionHandle_;
	// EVENT_TRACE_PROPERTIES* pSessionProperties;
	void* pSessionProperties_;

};

void configure_etw_provider(void);

#endif