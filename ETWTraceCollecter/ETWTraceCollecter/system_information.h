#ifndef TRACE_COLLECTER_SYSTEM_INFORMATION
#define TRACE_COLLECTER_SYSTEM_INFORMATION

#include <Windows.h>
#include <unordered_map>
#include <set>


using namespace std;

class system_information{
public:
	// Variables as buffer for the "trace_parser"
	// Should be put in private space when involved in multi_thread, but let put it here for testing for now.
	DWORD processer_processid_map[4];

	unordered_map<DWORD, short> ParmToNum;
	unordered_map<DWORD, DWORD> messageID_Map; // ALPC

	unordered_map<DWORD, wchar_t*> processid_name_map;
	unordered_map<DWORD, DWORD> threadid_processid_map;
	unordered_map<DWORD, wstring> keyname_parameter_map;


	system_information();

private:
	 set<DWORD> pid_whitelist;
	 set<wstring> pname_whitelist;

	 void get_all_process(void);
	 void get_all_thread(void);
};

#endif