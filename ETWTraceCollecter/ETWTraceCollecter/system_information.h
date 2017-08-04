#ifndef TRACE_COLLECTER_SYSTEM_INFORMATION
#define TRACE_COLLECTER_SYSTEM_INFORMATION

#include <Windows.h>
#include <unordered_map>
#include <set>


using namespace std;

class system_information{
public:
	system_information();

private:
	 unordered_map<DWORD, wchar_t*> processid_name_map;
	 unordered_map<DWORD, DWORD> threadid_processid_map;

	 set<DWORD> pid_whitelist;
	 set<wstring> pname_whitelist;

	 void get_all_process(void);
	 void get_all_thread(void);
};

#endif