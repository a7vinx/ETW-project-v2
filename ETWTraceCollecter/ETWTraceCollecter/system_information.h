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
	DWORD curPID[4];
	int parmnum;

	unordered_map<DWORD, short> ParmToNum;
	unordered_map<DWORD, DWORD> messageID_Map;

	unordered_map<DWORD, wchar_t*> processid_name_map;
	unordered_map<DWORD, DWORD> threadid_processid_map;

	struct hash_func{
		int operator()(const wchar_t * str)const{
			int seed = 131; // 31  131 1313 13131131313 etc
			int hash = 0;
			while (*str){
				hash = (hash * seed) + (*str);
				str++;
			}

			return hash & (0x7FFFFFFF);
		}
	};
	struct cmp{
		bool operator()(const wchar_t *str1, const wchar_t * str2)const{
			return wcscmp(str1, str2) == 0;
		}
	};
	unordered_map<const wchar_t*, int, hash_func, cmp> ParaList;

	system_information();

private:
	 set<DWORD> pid_whitelist;
	 set<wstring> pname_whitelist;

	 void get_all_process(void);
	 void get_all_thread(void);
};

#endif