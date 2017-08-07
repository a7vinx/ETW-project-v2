#include <windows.h>
#include <tlhelp32.h> // the order of including <windows.h> & <tlhelp32.h> matters

#include <unordered_map>
#include <set>

#include "system_information.h"


using namespace std;

system_information::system_information() {
	pid_whitelist.insert(GetCurrentProcessId());

	get_all_process();
	get_all_thread();

	curPID[4] = { 0L };
	parmnum = 255;
}

void system_information::get_all_process(void){
	HANDLE   hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32   procentry;
	procentry.dwSize = sizeof(PROCESSENTRY32);
	BOOL   bFlag = Process32First(hSnapShot, &procentry);
	while (bFlag) {
		int len = wcslen(procentry.szExeFile);
		processid_name_map[procentry.th32ProcessID] = (wchar_t*)malloc((len + 1)*sizeof(wchar_t));
		int i = 0;
		wchar_t* st = processid_name_map[procentry.th32ProcessID];

		//try to find out the PIDs for the processes in the whitelist
		wstring temp = wstring(procentry.szExeFile);
		if (pname_whitelist.find(temp) != pname_whitelist.end())
			pid_whitelist.insert(procentry.th32ProcessID);

		while ((procentry.szExeFile[i]) != 0) {
			*st = procentry.szExeFile[i];
			st += 1;
			i += 1;
		}
		*st = 0;
		bFlag = Process32Next(hSnapShot, &procentry);
	}
}

void system_information::get_all_thread(void){
	HANDLE   hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	THREADENTRY32   thrcentry;
	thrcentry.dwSize = sizeof(THREADENTRY32);
	BOOL   bFlag = Thread32First(hSnapShot, &thrcentry);
	while (bFlag) {
		threadid_processid_map[thrcentry.th32ThreadID] = thrcentry.th32OwnerProcessID;
		bFlag = Thread32Next(hSnapShot, &thrcentry);
	}
}

