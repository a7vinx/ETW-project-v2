#include <windows.h>
#include <stdio.h>
#include <wbemidl.h>
#include <wmistr.h>
#include <evntrace.h>
#include <tdh.h> //PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD
#include <in6addr.h>
#include <dia2.h>

#include "trace_parser.h"
#include "system_information.h"
#include "getAddress.h"

using namespace std;

trace_parser::trace_parser(){
	//producer_position = 0;
	//consumer_position = 0;
	sys_info;
	syscall_addr;

}

system_information trace_parser::sys_info;
getAddress trace_parser::syscall_addr;

// Parse the buffered event.
output_format trace_parser::parse_event(trace_buffer_format trace){
	// The output data should be store in ouput, and be return.
	output_format output;
	output.event_type = 0;

	DWORD status = ERROR_SUCCESS;
	DWORD pUserData;
	DWORD PointerSize = 0;
	ULONGLONG TimeStamp = 0;
	ULONGLONG Nanoseconds = 0;
	BOOL finishOP = false;
	UCHAR OPcode = trace.event_header.EventDescriptor.Opcode;
	if (IsEqualGUID(trace.event_header.ProviderId, EventTraceGuid) && (!OPcode)){
	        wprintf(L"A Event is being skipped\n");
	        ; // Skip this event.
	}
	// Skips the event if it is not SysClEnter(51) or CSwitch(36).
	else
	if ((OPcode == 10 && trace.event_header.ProviderId.Data1 == 0xae53722e)
		|| (OPcode == 11 && trace.event_header.ProviderId.Data1 == 0xae53722e)
		|| (OPcode == 13 && trace.event_header.ProviderId.Data1 == 0xae53722e)
		|| (OPcode == 16 && trace.event_header.ProviderId.Data1 == 0xae53722e)
		|| (OPcode == 51)
		|| (OPcode == 10 && trace.event_header.ProviderId.Data1 == 0x2cb15d1d)
		|| (OPcode == 32 && trace.event_header.ProviderId.Data1 == 0x90cbdc39)
		|| (OPcode == 64 && trace.event_header.ProviderId.Data1 == 0x90cbdc39)
		|| (OPcode == 33 && trace.event_header.ProviderId.Data1 == 0x45d8cccd)
		|| (OPcode == 34 && trace.event_header.ProviderId.Data1 == 0x45d8cccd)
		|| (OPcode == 1 && trace.event_header.ProviderId.Data1 == 0x3d6fa8d1)
		|| (OPcode == 36 && trace.event_header.ProviderId.Data1 == 0x3d6fa8d1)
		|| (OPcode == 1 && trace.event_header.ProviderId.Data1 == 0x3d6fa8d0)){
			pUserData = (DWORD)trace.user_data;
			if (OPcode == 51){
				DWORD address = (*(DWORD *)pUserData) & 0xFFFFFFF;
				if (syscall_addr.addressToName.find(address) != syscall_addr.addressToName.end())
					output.systemcall_parameter = syscall_addr.addressToName[address];
				else goto cleanup;
				output.current_process_id = sys_info.processer_processid_map[trace.buffer_context.ProcessorNumber];
				finishOP = true;
				goto cleanup;
			}
			else
			if ((OPcode == 33 && trace.event_header.ProviderId.Data1 == 0x45d8cccd)
				|| (OPcode == 34 && trace.event_header.ProviderId.Data1 == 0x45d8cccd)){
				if (OPcode == 33){
					DWORD messageID = *(DWORD*)(pUserData);
					output.current_process_id = trace.event_header.ProcessId;
					sys_info.messageID_Map[messageID] = output.current_process_id;
					goto cleanup;
				}
				else{
					output.current_process_id = trace.event_header.ProcessId;
					DWORD messageID = *(DWORD*)(pUserData);
					if (sys_info.messageID_Map.find(messageID) != sys_info.messageID_Map.end() && sys_info.processid_name_map.find(sys_info.messageID_Map[messageID]) != sys_info.processid_name_map.end()){
						finishOP = true;
						output.systemcall_parameter = sys_info.processid_name_map[sys_info.messageID_Map[messageID]];
					}
					if (sys_info.processid_name_map.find(output.current_process_id) != sys_info.processid_name_map.end()){
						finishOP = true;
						output.systemcall_parameter = sys_info.processid_name_map[output.current_process_id];
						output.current_process_id = sys_info.messageID_Map[messageID];
					}
					goto cleanup;
				}
			}
			else
			if (OPcode == 1 && trace.event_header.ProviderId.Data1 == 0x3d6fa8d0){
				pUserData += 8;
				output.current_process_id = *(DWORD*)pUserData;
				pUserData += 40;
				pUserData += GetLengthSid((PVOID)(pUserData));
				int len = strlen((char *)pUserData);
				if (trace.event_header.EventDescriptor.Opcode == 1 || trace.event_header.EventDescriptor.Opcode == 3){
					/*wstring oname = ProcessName_map[output.current_process_id];
					if (whiteListPName.find(oname) != whiteListPName.end())
					{
					if (whiteListPID.find(output.current_process_id) != whiteListPID.end())
					whiteListPID.erase(output.current_process_id);
					}*/

					sys_info.processid_name_map[output.current_process_id] = (wchar_t*)malloc((len + 1)*sizeof(wchar_t));
					int i = 0;
					wchar_t* st = sys_info.processid_name_map[output.current_process_id];
					wchar_t* stemp = st;
					char* ch = (char *)pUserData;
					while ((*ch) != 0){
						*st = (wchar_t)(*ch);
						st += 1;
						ch += 1;
						i += 1;
					}
					*st = 0;

					/* wstring temp = wstring(stemp);
					if (whiteListPName.find(temp) != whiteListPName.end())
					whiteListPID.insert(output.current_process_id);*/
				}
				goto cleanup;
			}
			else
			if (OPcode == 1 && trace.event_header.ProviderId.Data1 == 0x3d6fa8d1){
					   output.current_process_id = *(DWORD*)pUserData;
					   pUserData += 4;
					   DWORD threadid = *(DWORD*)pUserData;
					   sys_info.threadid_processid_map[threadid] = output.current_process_id;
					   goto cleanup;
				}
				else
				if ((OPcode == 10 || OPcode == 13 || OPcode == 16 || OPcode == 11) && trace.event_header.ProviderId.Data1 == 0xae53722e){
					   pUserData += 16;
					   DWORD keyhandle = *(DWORD*)pUserData;
					   if (OPcode == 10 || OPcode == 11){
							 pUserData += 8;
							 DWORD last_backslash = pUserData;
							 while (*(unsigned short*)pUserData != 0 && *(unsigned short*)pUserData != 0x7B){
									pUserData += 2;
							 }
							 *(unsigned short*)pUserData = 0;
							 output.systemcall_parameter = (wchar_t*)last_backslash;
							 sys_info.keyname_parameter_map[keyhandle] = output.systemcall_parameter;
					   }
					   else{
							 if (sys_info.keyname_parameter_map.find(keyhandle) == sys_info.keyname_parameter_map.end()) goto cleanup; 
							 else output.systemcall_parameter = sys_info.keyname_parameter_map[keyhandle];
					   }
					  
					   output.current_process_id = trace.event_header.ProcessId;
					   finishOP = true;
					   goto cleanup;
				}
				else
				if (OPcode == 32 && pUserData&& trace.event_header.ProviderId.Data1 == 0x90cbdc39){
					   //fileObject = *(DWORD *)pUserData;
					   pUserData += 8;
					   //strName = "NtCreateFile";
					   DWORD last_backslash = pUserData;
					   while (*(unsigned short*)pUserData != 0 && *(unsigned short*)pUserData != 0x7B){
							 pUserData += 2;
					   }
					   *(unsigned short*)pUserData = 0;
					   output.systemcall_parameter = (wchar_t*)last_backslash;
					   output.current_process_id = sys_info.processer_processid_map[trace.buffer_context.ProcessorNumber];
					   finishOP = true;
					   goto cleanup;
				}
				else
				if (OPcode == 36 && trace.event_header.ProviderId.Data1 == 1030727889){
					   DWORD threadID = *(DWORD *)pUserData;
					   int processorID = trace.buffer_context.ProcessorNumber;
					   sys_info.processer_processid_map[processorID] = GetProcessIdOfThread(OpenThread(THREAD_QUERY_INFORMATION, false, threadID));
					   if (sys_info.processer_processid_map[processorID] == 0) sys_info.processer_processid_map[processorID] = sys_info.threadid_processid_map[threadID];
					   goto cleanup;
				}
				if (OPcode == 64 && trace.event_header.ProviderId.Data1 == 0x90cbdc39){
					   pUserData += 8;
					   DWORD threadID = *(DWORD *)pUserData;
					   output.current_process_id = GetProcessIdOfThread(OpenThread(THREAD_QUERY_INFORMATION, false, threadID));
					   if (!output.current_process_id) output.current_process_id = sys_info.threadid_processid_map[threadID];
					   pUserData += 8;
					   //fileObject = *(DWORD*)pUserData;
					   pUserData += 20;
					   //strName = "NtCreateFile";
					   DWORD last_backslash = pUserData;
					   while (*(unsigned short*)pUserData != 0 && *(unsigned short*)pUserData != 0x7B){
							 pUserData += 2;
					   }
					   *(unsigned short*)pUserData = 0;
					   output.systemcall_parameter = (wchar_t*)last_backslash;
					   finishOP = true;
					   goto cleanup;
				}
				else
				if (OPcode == 10 && trace.event_header.ProviderId.Data1 == 0x2cb15d1d){
					   pUserData += 16;
					   output.current_process_id = *(DWORD*)pUserData;
					   pUserData += 40;
					   //strName = "NtOpenSection";
					   DWORD last_backslash = pUserData;
					   while (*(unsigned short*)pUserData != 0 && *(unsigned short*)pUserData != 0x7B){
							 pUserData += 2;
					   }
					   *(unsigned short*)pUserData = 0;
					   output.systemcall_parameter = (wchar_t*)last_backslash;
					   output.current_process_id = trace.event_header.ProcessId;
					   finishOP = true;
					   goto cleanup;
				}
	}
cleanup:
	if (finishOP)
		output.event_type = OPcode;
		
	return output;
}
