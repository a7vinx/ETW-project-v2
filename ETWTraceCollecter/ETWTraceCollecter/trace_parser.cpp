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

	DWORD status = ERROR_SUCCESS;
	DWORD pUserData;
	DWORD PointerSize = 0;
	ULONGLONG TimeStamp = 0;
	ULONGLONG Nanoseconds = 0;
	BOOL finishOP = false;
	int CPID = 0;
	UCHAR OPcode = trace.event_hander.EventDescriptor.Opcode;
	if (IsEqualGUID(trace.event_hander.ProviderId, EventTraceGuid) &&
	        (!OPcode))
	{
	        wprintf(L"A Event is being skipped\n");
	        ; // Skip this event.
	}
	// Skips the event if it is not SysClEnter(51) or CSwitch(36).
	else
	if ((OPcode == 10 && trace.event_hander.ProviderId.Data1 == 0xae53722e)
		|| (OPcode == 11 && trace.event_hander.ProviderId.Data1 == 0xae53722e)
		|| (OPcode == 13 && trace.event_hander.ProviderId.Data1 == 0xae53722e)
		|| (OPcode == 16 && trace.event_hander.ProviderId.Data1 == 0xae53722e)
		|| (OPcode == 51)
		|| (OPcode == 10 && trace.event_hander.ProviderId.Data1 == 0x2cb15d1d)
		|| (OPcode == 32 && trace.event_hander.ProviderId.Data1 == 0x90cbdc39)
		|| (OPcode == 64 && trace.event_hander.ProviderId.Data1 == 0x90cbdc39)
		|| (OPcode == 33 && trace.event_hander.ProviderId.Data1 == 0x45d8cccd)
		|| (OPcode == 34 && trace.event_hander.ProviderId.Data1 == 0x45d8cccd)
		|| (OPcode == 1 && trace.event_hander.ProviderId.Data1 == 0x3d6fa8d1)
		|| (OPcode == 36 && trace.event_hander.ProviderId.Data1 == 0x3d6fa8d1)
		|| (OPcode == 1 && trace.event_hander.ProviderId.Data1 == 0x3d6fa8d0)){
			pUserData = (DWORD)trace.user_data;
			if (OPcode == 51){
				DWORD address = (*(DWORD *)pUserData) & 0xFFFFFFF;
				if (syscall_addr.addressToName.find(address) != syscall_addr.addressToName.end())
					sys_info.parmnum = sys_info.ParmToNum[address];
				else goto cleanup;
				output.event_type = 46;
				CPID = sys_info.curPID[trace.buffer_context.ProcessorNumber];
				finishOP = true;
				goto cleanup;
			}
			else
			if ((OPcode == 33 && trace.event_hander.ProviderId.Data1 == 0x45d8cccd)
				|| (OPcode == 34 && trace.event_hander.ProviderId.Data1 == 0x45d8cccd)){
				if (OPcode == 33){
					DWORD messageID = *(DWORD*)(pUserData);
					CPID = trace.event_hander.ProcessId;
					sys_info.messageID_Map[messageID] = CPID;
					goto cleanup;
				}
				else{
					CPID = trace.event_hander.ProcessId;
					DWORD messageID = *(DWORD*)(pUserData);
					if (sys_info.messageID_Map.find(messageID) != sys_info.messageID_Map.end() && sys_info.processid_name_map.find(sys_info.messageID_Map[messageID]) != sys_info.processid_name_map.end() && sys_info.ParaList.find(sys_info.processid_name_map[sys_info.messageID_Map[messageID]]) != sys_info.ParaList.end()){
						output.event_type = 38;
						finishOP = true;
						sys_info.parmnum = sys_info.ParaList[sys_info.processid_name_map[sys_info.messageID_Map[messageID]]];
					}
					if (sys_info.processid_name_map.find(CPID) != sys_info.processid_name_map.end() && sys_info.ParaList.find(sys_info.processid_name_map[CPID]) != sys_info.ParaList.end()){
						output.event_type = 39;
						finishOP = true;
						sys_info.parmnum = sys_info.ParaList[sys_info.processid_name_map[CPID]];
						CPID = sys_info.messageID_Map[messageID];
					}
					goto cleanup;
				}
			}
			else
			if (OPcode == 1 && trace.event_hander.ProviderId.Data1 == 0x3d6fa8d0){
				pUserData += 8;
				CPID = *(DWORD*)pUserData;
				pUserData += 40;
				pUserData += GetLengthSid((PVOID)(pUserData));
				int len = strlen((char *)pUserData);
				if (trace.event_hander.EventDescriptor.Opcode == 1 || trace.event_hander.EventDescriptor.Opcode == 3){
					/*wstring oname = ProcessName_map[CPID];
					if (whiteListPName.find(oname) != whiteListPName.end())
					{
					if (whiteListPID.find(CPID) != whiteListPID.end())
					whiteListPID.erase(CPID);
					}*/

					sys_info.processid_name_map[CPID] = (wchar_t*)malloc((len + 1)*sizeof(wchar_t));
					int i = 0;
					wchar_t* st = sys_info.processid_name_map[CPID];
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
					whiteListPID.insert(CPID);*/
				}
				goto cleanup;
			}
			else
			//if (OPcode == 1 && trace.event_hander.ProviderId.Data1 == 0x3d6fa8d1){
			//		   CPID = *(DWORD*)pUserData;
			//		   pUserData += 4;
			//		   DWORD threadid = *(DWORD*)pUserData;
			//		   sys_info.threadid_processid_map[threadid] = CPID;
			//		   goto cleanup;
			//	}
			//	else
			//	if ((OPcode == 10 || OPcode == 13 || OPcode == 16 || OPcode == 11) && trace.event_hander.ProviderId.Data1 == 0xae53722e){
			//		   pUserData += 16;
			//		   DWORD keyhandle = *(DWORD*)pUserData;
			//		   if (OPcode == 10 || OPcode == 11){
			//				 pUserData += 8;
			//				 DWORD last_backslash = pUserData;
			//				 while (*(unsigned short*)pUserData != 0 && *(unsigned short*)pUserData != 0x7B){
			//						pUserData += 2;
			//				 }
			//				 *(unsigned short*)pUserData = 0;
			//				 parm = (wchar_t*)last_backslash;
			//				 if (ParaList.find(parm) == ParaList.end()) goto cleanup; else parmnum = ParaList[parm];
			//				 keyname_map[keyhandle] = parmnum;
			//		   }
			//		   else{
			//				 if (keyname_map.find(keyhandle) == keyname_map.end()) goto cleanup; else parmnum = keyname_map[keyhandle];
			//		   }
			//		   switch (OPcode)
			//		   {
			//		   case 10:{
			//							   EventType = 42;
			//							   break;
			//		   }
			//		   case 11:{
			//							   EventType = 43;
			//							   break;
			//		   }
			//		   case 13:{
			//							   EventType = 44;
			//							   break;
			//		   }
			//		   case 16:{
			//							   EventType = 45;
			//							   break;
			//		   }
			//		   }
			//		   CPID = pEvent->EventHeader.ProcessId;
			//		   finishOP = true;
			//		   goto cleanup;
			//	}
			//	else
			//	if (OPcode == 32 && pUserData&& pEvent->EventHeader.ProviderId.Data1 == 0x90cbdc39){
			//		   //fileObject = *(DWORD *)pUserData;
			//		   pUserData += 8;
			//		   //strName = "NtCreateFile";
			//		   DWORD last_backslash = pUserData;
			//		   while (*(unsigned short*)pUserData != 0 && *(unsigned short*)pUserData != 0x7B){
			//				 pUserData += 2;
			//		   }
			//		   *(unsigned short*)pUserData = 0;
			//		   parm = (wchar_t*)last_backslash;
			//		   if (ParaList.find(parm) == ParaList.end()) goto cleanup; else parmnum = ParaList[parm];
			//		   EventType = 40;
			//		   CPID = curPID[pEvent->BufferContext.ProcessorNumber];
			//		   finishOP = true;
			//		   goto cleanup;
			//	}
			//	else
			//	if (OPcode == 36 && pEvent->EventHeader.ProviderId.Data1 == 1030727889){
			//		   DWORD threadID = *(DWORD *)pUserData;
			//		   int processorID = pEvent->BufferContext.ProcessorNumber;
			//		   curPID[processorID] = GetProcessIdOfThread(OpenThread(THREAD_QUERY_INFORMATION, false, threadID));
			//		   if (curPID[processorID] == 0) curPID[processorID] = ThreadIDtoPID_map[threadID];
			//		   goto cleanup;
			//	}
			//	if (OPcode == 64 && pEvent->EventHeader.ProviderId.Data1 == 0x90cbdc39){
			//		   pUserData += 8;
			//		   DWORD threadID = *(DWORD *)pUserData;
			//		   CPID = GetProcessIdOfThread(OpenThread(THREAD_QUERY_INFORMATION, false, threadID));
			//		   if (!CPID) CPID = ThreadIDtoPID_map[threadID];
			//		   pUserData += 8;
			//		   fileObject = *(DWORD*)pUserData;
			//		   pUserData += 20;
			//		   //strName = "NtCreateFile";
			//		   DWORD last_backslash = pUserData;
			//		   while (*(unsigned short*)pUserData != 0 && *(unsigned short*)pUserData != 0x7B){
			//				 pUserData += 2;
			//		   }
			//		   *(unsigned short*)pUserData = 0;
			//		   parm = (wchar_t*)last_backslash;
			//		   if (ParaList.find(parm) == ParaList.end()) goto cleanup; else parmnum = ParaList[parm];
			//		   EventType = 40;
			//		   finishOP = true;
			//		   goto cleanup;
			//	}
			//	else
			//	if (OPcode == 10 && pEvent->EventHeader.ProviderId.Data1 == 0x2cb15d1d){
			//		   pUserData += 16;
			//		   CPID = *(DWORD*)pUserData;
			//		   pUserData += 40;
			//		   //strName = "NtOpenSection";
			//		   DWORD last_backslash = pUserData;
			//		   while (*(unsigned short*)pUserData != 0 && *(unsigned short*)pUserData != 0x7B){
			//				 pUserData += 2;
			//		   }
			//		   *(unsigned short*)pUserData = 0;
			//		   parm = (wchar_t*)last_backslash;
			//		   if (ParaList.find(parm) == ParaList.end()) goto cleanup; else parmnum = ParaList[parm];
			//		   EventType = 41;
			//		   CPID = pEvent->EventHeader.ProcessId;
			//		   finishOP = true;
			//		   goto cleanup;
			//	}
		 cleanup:

		 //if (!pidInWhitelist(CPID) && finishOP)
		 //{
			 //if (MessageCount % MaxSendNum == 0 && MessageCount != 0){
				// try {
				//	 message.reset(session->createBytesMessage(data, MaxSendNum * 6));
				// }
				// catch (CMSException e){
				//	 cout << e.getMessage();
				//	 auto_ptr<Session> ss(connection->createSession());
				//	 session = ss;
				// }

				// producer->send(message.get());
			 //}
			 //if (couteachprocesseventnumber.find(CPID) != couteachprocesseventnumber.end()){
				// couteachprocesseventnumber[CPID]++;
			 //}
			 //else{
				// couteachprocesseventnumber[CPID] = 1;
			 //}
			 //data[(MessageCount%MaxSendNum) * 6] = couteachprocesseventnumber[CPID] % 255 + 1;
			 //data[(MessageCount%MaxSendNum) * 6 + 1] = (couteachprocesseventnumber[CPID] / 255) % 255 + 1;
			 //data[(MessageCount%MaxSendNum) * 6 + 2] = CPID % 255 + 1;
			 //data[(MessageCount%MaxSendNum) * 6 + 3] = (CPID / 255) % 255 + 1;
			 //data[(MessageCount%MaxSendNum) * 6 + 4] = parmnum + 1;
			 //data[(MessageCount%MaxSendNum) * 6 + 5] = EventType + 1;
			 //MessageCount++;

			 //string messageBody = ss.str();
			 //reset
			 //message.reset(session->createTextMessage(boost::asio::buffer(data)));
			 //                   cout << data << endl;
			 //send to activeMQ
			 //output to local file
			 //outFile << messageBody.c_str() << endl;
			 //outFile << data << endl;
			 //outFile << hex << (((strnum << 1) + parmnum / 256) << 24) + (parmnum % 256 << 16) + (CPID / 256 << 8) + CPID % 256 << ' ';
			 //cout << messageBody.c_str() << endl;
			 //int ret;
			 //if ((ret = send(sockClient, (char*)&data, 4, 0)) < 0)
			 //     {
			 //            printf("errno: %d\n", WSAGetLastError());
			 //     }
			 //if (MessageCount % 10000 == 0)
			 //{
				// //wcout << L"published " << MessageCount << L" messages!" << endl;
			 //}
		 //}
		 sys_info.parmnum = 255;
		 output.event_type = 255;

		 //if (ERROR_SUCCESS != status || NULL == pUserData)
		 //{
			// CloseTrace(g_hTrace);
		 //}
	}

	return output;
}
