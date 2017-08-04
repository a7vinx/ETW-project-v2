#ifndef TRACE_COLLECTER_GETADDRESS
#define TRACE_COLLECTER_GETADDRESS

#include <stdio.h>
#include <fstream>
#include <iostream>
#include <vector>
#include <unordered_map>

#include "include/dia2.h"
#include "include/ntdll.h"


using namespace std;

class getAddress
{
public:
	unordered_map<DWORD, wchar_t*> addressToName;

	getAddress(void);
	~getAddress(void);
	PVOID GetAllProcAddrFromKernelPdb();
	bool FindPublicAll(IDiaSymbol *pGlobal);
	PVOID GetProcAddrFromKernelPdb(wchar_t* zPdbName, wchar_t* szApiName);

};

#endif