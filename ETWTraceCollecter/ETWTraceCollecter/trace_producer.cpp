#include <windows.h>
#include <stdio.h>
#include <wbemidl.h>
#include <wmistr.h>
#include <evntrace.h>
#include <tdh.h> //PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD
#include <in6addr.h>
#include <dia2.h>

#include "trace_producer.h"

using namespace std;

trace_producer::trace_producer(){
	//producer_position = 0;
	//consumer_position = 0;
}

// The function will set up the etw producer and call the call_back function.
void trace_producer::setup_event_producer(){
	EVENT_TRACE_LOGFILE event_logfile;
	TRACE_LOGFILE_HEADER* event_logfile_header;
	TRACEHANDLE event_logfile_handle;
	BOOL event_usermode = FALSE;

begin:
	event_logfile_header = &event_logfile.LogfileHeader;
	ZeroMemory(&event_logfile, sizeof(EVENT_TRACE_LOGFILE));
	event_logfile.LoggerName = KERNEL_LOGGER_NAME;

	// consum_event() is the callback function. should be writed in this class.
	// If everything go well, the program will be block here.
	event_logfile.EventRecordCallback = (PEVENT_RECORD_CALLBACK)(consum_event);

	event_logfile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
	event_logfile_handle = OpenTrace(&event_logfile);
	if (INVALID_PROCESSTRACE_HANDLE == event_logfile_handle){
		wprintf(L"OpenTrace failed with %lu\n", GetLastError());
		goto cleanup;
	}

	event_usermode = event_logfile_header->LogFileMode & EVENT_TRACE_PRIVATE_LOGGER_MODE;
	if (event_logfile_header->PointerSize != sizeof(PVOID)){
		event_logfile_header = (PTRACE_LOGFILE_HEADER)((PUCHAR)event_logfile_header +
			2 * (event_logfile_header->PointerSize - sizeof(PVOID)));
	}

	TDHSTATUS temp_status = ProcessTrace(&event_logfile_handle, 1, 0, 0);
	if (temp_status != ERROR_SUCCESS && temp_status != ERROR_CANCELLED){
		wprintf(L"ProcessTrace failed with %lu\n", temp_status);
		goto cleanup;
	}

cleanup:
	if (INVALID_PROCESSTRACE_HANDLE != event_logfile_handle){
		temp_status = CloseTrace(event_logfile_handle);
	}
	goto begin;
}

// The call_back function, in this case it should parser the pHeader and write important information to the trace_buffer.
VOID WINAPI trace_producer::consum_event(PEVENT_RECORD event_pointer){
	//unique_lock<mutex> lock(bufferMutex);

	//notFullCv.wait(lock, [=] {return pEventBufferSize < BUFFERSIZE; });

	{
		// This function can't use member variables.
		extern trace_buffer_format trace_buffer[TRACE_BUFFER_SIZE];
		extern int producer_position;

		//pEventBuffer[producterPos] = pEvent;
		trace_buffer[producer_position].user_data = event_pointer->UserData;
		//trace_buffer[producer_position].user_data_size = event_pointer->UserDataLength;
		trace_buffer[producer_position].buffer_context = event_pointer->BufferContext;
		trace_buffer[producer_position].event_hander = event_pointer->EventHeader;

		//cout << (event_pointer->EventHeader).Size << "+" << event_pointer->UserDataLength << "=" << (event_pointer->EventHeader).Size + event_pointer->UserDataLength << "?=" << event_pointer->UserData;

		producer_position = (producer_position + 1) % TRACE_BUFFER_SIZE;
	}

	//lock.unlock();

	//notEmptyCv.notify_one();
	////notEmptyCv.notify_all();
}

//// Parse the buffered event.
//void trace_producer::parse_event(trace_buffer_format trace){
//     DWORD status = ERROR_SUCCESS;
//     DWORD pUserData;
//     DWORD PointerSize = 0;
//     ULONGLONG TimeStamp = 0;
//     ULONGLONG Nanoseconds = 0;
//     BOOL finishOP = false;
//     int CPID = 0;
//     UCHAR OPcode = pEvent->EventHeader.EventDescriptor.Opcode;
//     if (IsEqualGUID(pEvent->EventHeader.ProviderId, EventTraceGuid) &&
//            (!OPcode))
//     {
//            wprintf(L"A Event is being skipped\n");
//            ; // Skip this event.
//     }
//     // Skips the event if it is not SysClEnter(51) or CSwitch(36).
//     else
//     if (
//            (OPcode == 10 && pEvent->EventHeader.ProviderId.Data1 == 0xae53722e)
//            || (OPcode == 11 && pEvent->EventHeader.ProviderId.Data1 == 0xae53722e)
//            || (OPcode == 13 && pEvent->EventHeader.ProviderId.Data1 == 0xae53722e)
//            || (OPcode == 16 && pEvent->EventHeader.ProviderId.Data1 == 0xae53722e)
//            || (OPcode == 51)
//            || (OPcode == 10 && pEvent->EventHeader.ProviderId.Data1 == 0x2cb15d1d)
//            || (OPcode == 32 && pEvent->EventHeader.ProviderId.Data1 == 0x90cbdc39)
//            || (OPcode == 64 && pEvent->EventHeader.ProviderId.Data1 == 0x90cbdc39)
//            || (OPcode == 33 && pEvent->EventHeader.ProviderId.Data1 == 0x45d8cccd)
//            || (OPcode == 34 && pEvent->EventHeader.ProviderId.Data1 == 0x45d8cccd)
//            || (OPcode == 1 && pEvent->EventHeader.ProviderId.Data1 == 0x3d6fa8d1)
//            || (OPcode == 36 && pEvent->EventHeader.ProviderId.Data1 == 0x3d6fa8d1)
//            || (OPcode == 1 && pEvent->EventHeader.ProviderId.Data1 == 0x3d6fa8d0)
//
//            )
//     {
//            pUserData = (DWORD)pEvent->UserData;
//            if (OPcode == 51){
//                   DWORD address = (*(DWORD *)pUserData) & 0xFFFFFFF;
//                   if (g.addressToName.find(address) != g.addressToName.end())
//                         parmnum = ParmToNum[address];
//                   else goto cleanup;
//                   EventType = 46;
//                   CPID = curPID[pEvent->BufferContext.ProcessorNumber];
//                   finishOP = true;
//                   goto cleanup;
//            }
//            else
//            if ((OPcode == 33 && pEvent->EventHeader.ProviderId.Data1 == 0x45d8cccd)
//                   || (OPcode == 34 && pEvent->EventHeader.ProviderId.Data1 == 0x45d8cccd)){
//                   if (OPcode == 33)
//                   {
//                         DWORD messageID = *(DWORD*)(pUserData);
//                         CPID = pEvent->EventHeader.ProcessId;
//                         messageID_Map[messageID] = CPID;
//                         goto cleanup;
//                   }
//                   else
//                   {
//                         CPID = pEvent->EventHeader.ProcessId;
//                         DWORD messageID = *(DWORD*)(pUserData);
//                         if (messageID_Map.find(messageID) != messageID_Map.end() && ProcessName_map.find(messageID_Map[messageID]) != ProcessName_map.end() && ParaList.find(ProcessName_map[messageID_Map[messageID]]) != ParaList.end()){
//                                EventType = 38;
//                                finishOP = true;
//                                parmnum = ParaList[ProcessName_map[messageID_Map[messageID]]];
//                         }
//                         if (ProcessName_map.find(CPID) != ProcessName_map.end() && ParaList.find(ProcessName_map[CPID]) != ParaList.end()){
//                                EventType = 39;
//                                finishOP = true;
//                                parmnum = ParaList[ProcessName_map[CPID]];
//                                CPID = messageID_Map[messageID];
//                         }
//                         goto cleanup;
//                   }
//            }
//            else
//            if (OPcode == 1 && pEvent->EventHeader.ProviderId.Data1 == 0x3d6fa8d0){
//                   pUserData += 8;
//                   CPID = *(DWORD*)pUserData;
//                   pUserData += 40;
//                   pUserData += GetLengthSid((PVOID)(pUserData));
//                   int len = strlen((char *)pUserData);
//                   if (pEvent->EventHeader.EventDescriptor.Opcode == 1 || pEvent->EventHeader.EventDescriptor.Opcode == 3){
//                         /*wstring oname = ProcessName_map[CPID];
//                         if (whiteListPName.find(oname) != whiteListPName.end())
//                         {
//                         if (whiteListPID.find(CPID) != whiteListPID.end())
//                         whiteListPID.erase(CPID);
//                         }*/
//
//                         ProcessName_map[CPID] = (wchar_t*)malloc((len + 1)*sizeof(wchar_t));
//                         int i = 0;
//                         wchar_t* st = ProcessName_map[CPID];
//                         wchar_t* stemp = st;
//                         char* ch = (char *)pUserData;
//                         while ((*ch) != 0){
//                                *st = (wchar_t)(*ch);
//                                st += 1;
//                                ch += 1;
//                                i += 1;
//                         }
//                         *st = 0;
//
//                         wstring temp = wstring(stemp);
//                         if (whiteListPName.find(temp) != whiteListPName.end())
//                                whiteListPID.insert(CPID);
//                   }
//                   goto cleanup;
//            }
//            else
//            if (OPcode == 1 && pEvent->EventHeader.ProviderId.Data1 == 0x3d6fa8d1){
//                   CPID = *(DWORD*)pUserData;
//                   pUserData += 4;
//                   DWORD threadid = *(DWORD*)pUserData;
//                   ThreadIDtoPID_map[threadid] = CPID;
//                   goto cleanup;
//            }
//            else
//            if ((OPcode == 10 || OPcode == 13 || OPcode == 16 || OPcode == 11) && pEvent->EventHeader.ProviderId.Data1 == 0xae53722e){
//                   pUserData += 16;
//                   DWORD keyhandle = *(DWORD*)pUserData;
//                   if (OPcode == 10 || OPcode == 11){
//                         pUserData += 8;
//                         DWORD last_backslash = pUserData;
//                         while (*(unsigned short*)pUserData != 0 && *(unsigned short*)pUserData != 0x7B){
//                                pUserData += 2;
//                         }
//                         *(unsigned short*)pUserData = 0;
//                         parm = (wchar_t*)last_backslash;
//                         if (ParaList.find(parm) == ParaList.end()) goto cleanup; else parmnum = ParaList[parm];
//                         keyname_map[keyhandle] = parmnum;
//                   }
//                   else{
//                         if (keyname_map.find(keyhandle) == keyname_map.end()) goto cleanup; else parmnum = keyname_map[keyhandle];
//                   }
//                   switch (OPcode)
//                   {
//                   case 10:{
//                                       EventType = 42;
//                                       break;
//                   }
//                   case 11:{
//                                       EventType = 43;
//                                       break;
//                   }
//                   case 13:{
//                                       EventType = 44;
//                                       break;
//                   }
//                   case 16:{
//                                       EventType = 45;
//                                       break;
//                   }
//                   }
//                   CPID = pEvent->EventHeader.ProcessId;
//                   finishOP = true;
//                   goto cleanup;
//            }
//            else
//            if (OPcode == 32 && pUserData&& pEvent->EventHeader.ProviderId.Data1 == 0x90cbdc39){
//                   //fileObject = *(DWORD *)pUserData;
//                   pUserData += 8;
//                   //strName = "NtCreateFile";
//                   DWORD last_backslash = pUserData;
//                   while (*(unsigned short*)pUserData != 0 && *(unsigned short*)pUserData != 0x7B){
//                         pUserData += 2;
//                   }
//                   *(unsigned short*)pUserData = 0;
//                   parm = (wchar_t*)last_backslash;
//                   if (ParaList.find(parm) == ParaList.end()) goto cleanup; else parmnum = ParaList[parm];
//                   EventType = 40;
//                   CPID = curPID[pEvent->BufferContext.ProcessorNumber];
//                   finishOP = true;
//                   goto cleanup;
//            }
//            else
//            if (OPcode == 36 && pEvent->EventHeader.ProviderId.Data1 == 1030727889){
//                   DWORD threadID = *(DWORD *)pUserData;
//                   int processorID = pEvent->BufferContext.ProcessorNumber;
//                   curPID[processorID] = GetProcessIdOfThread(OpenThread(THREAD_QUERY_INFORMATION, false, threadID));
//                   if (curPID[processorID] == 0) curPID[processorID] = ThreadIDtoPID_map[threadID];
//                   goto cleanup;
//            }
//            if (OPcode == 64 && pEvent->EventHeader.ProviderId.Data1 == 0x90cbdc39){
//                   pUserData += 8;
//                   DWORD threadID = *(DWORD *)pUserData;
//                   CPID = GetProcessIdOfThread(OpenThread(THREAD_QUERY_INFORMATION, false, threadID));
//                   if (!CPID) CPID = ThreadIDtoPID_map[threadID];
//                   pUserData += 8;
//                   fileObject = *(DWORD*)pUserData;
//                   pUserData += 20;
//                   //strName = "NtCreateFile";
//                   DWORD last_backslash = pUserData;
//                   while (*(unsigned short*)pUserData != 0 && *(unsigned short*)pUserData != 0x7B){
//                         pUserData += 2;
//                   }
//                   *(unsigned short*)pUserData = 0;
//                   parm = (wchar_t*)last_backslash;
//                   if (ParaList.find(parm) == ParaList.end()) goto cleanup; else parmnum = ParaList[parm];
//                   EventType = 40;
//                   finishOP = true;
//                   goto cleanup;
//            }
//            else
//            if (OPcode == 10 && pEvent->EventHeader.ProviderId.Data1 == 0x2cb15d1d){
//                   pUserData += 16;
//                   CPID = *(DWORD*)pUserData;
//                   pUserData += 40;
//                   //strName = "NtOpenSection";
//                   DWORD last_backslash = pUserData;
//                   while (*(unsigned short*)pUserData != 0 && *(unsigned short*)pUserData != 0x7B){
//                         pUserData += 2;
//                   }
//                   *(unsigned short*)pUserData = 0;
//                   parm = (wchar_t*)last_backslash;
//                   if (ParaList.find(parm) == ParaList.end()) goto cleanup; else parmnum = ParaList[parm];
//                   EventType = 41;
//                   CPID = pEvent->EventHeader.ProcessId;
//                   finishOP = true;
//                   goto cleanup;
//            }
//     cleanup:
//            ioMutex.lock();
//
//            {
//                   if (!pidInWhitelist(CPID) && finishOP)
//                   {
//                         if (MessageCount % MaxSendNum == 0 && MessageCount != 0){
//                                try {
//                                       message.reset(session->createBytesMessage(data, MaxSendNum * 6));
//                                }
//                                catch (CMSException e){
//                                       cout << e.getMessage();
//                                       auto_ptr<Session> ss(connection->createSession());
//                                       session = ss;
//                                }
//
//                                producer->send(message.get());
//                         }
//                         if (couteachprocesseventnumber.find(CPID) != couteachprocesseventnumber.end()){
//                                couteachprocesseventnumber[CPID]++;
//                         }
//                         else{
//                                couteachprocesseventnumber[CPID] = 1;
//                         }
//                         data[(MessageCount%MaxSendNum) * 6] = couteachprocesseventnumber[CPID] % 255 + 1;
//                         data[(MessageCount%MaxSendNum) * 6 + 1] = (couteachprocesseventnumber[CPID] / 255) % 255 + 1;
//                         data[(MessageCount%MaxSendNum) * 6 + 2] = CPID % 255 + 1;
//                         data[(MessageCount%MaxSendNum) * 6 + 3] = (CPID / 255) % 255 + 1;
//                         data[(MessageCount%MaxSendNum) * 6 + 4] = parmnum + 1;
//                         data[(MessageCount%MaxSendNum) * 6 + 5] = EventType + 1;
//                         MessageCount++;
//
//                         cout << "outputing..." << endl;
//                         cout << data << endl;
//                         //string messageBody = ss.str();
//                         //reset
//                          //message.reset(session->createTextMessage(boost::asio::buffer(data)));
//                         //                   cout << data << endl;
//                         //send to activeMQ
//                         //output to local file
//                         //outFile << messageBody.c_str() << endl;
//                         //outFile << data << endl;
//                         //outFile << hex << (((strnum << 1) + parmnum / 256) << 24) + (parmnum % 256 << 16) + (CPID / 256 << 8) + CPID % 256 << ' ';
//                         //cout << messageBody.c_str() << endl;
//                         //int ret;
//                         //if ((ret = send(sockClient, (char*)&data, 4, 0)) < 0)
//                         //     {
//                         //            printf("errno: %d\n", WSAGetLastError());
//                         //     }
//                         if (MessageCount % 10000 == 0)
//                         {
//                                //wcout << L"published " << MessageCount << L" messages!" << endl;
//                         }
//                   }
//                   parmnum = 255;
//                   EventType = 255;
//                   //CloseTrace(g_hTrace);
//                   if (ERROR_SUCCESS != status || NULL == pUserData)
//                   {
//                         CloseTrace(g_hTrace);
//                   }
//            }
//
//            ioMutex.unlock();
//     }
//}
