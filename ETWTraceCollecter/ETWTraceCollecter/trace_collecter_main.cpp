#include <iostream>
#include <process.h>

#include "system_information.h"
#include "getAddress.h"
#include "etw_configuring.h"
#include "trace_producer.h"


using namespace std;

void wmain(int argc, char* argv[]){
	// Configure the ETW provider, so we can get the event we want and the output way.
	//configure_etw_provider();

	system_information sysinfo;
	getAddress g;
	trace_producer tp;


	cout << endl;
}