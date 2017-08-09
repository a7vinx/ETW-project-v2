#define OUTPUT_SIZE 100

//void setup_event_producer();
VOID __cdecl setup_event_producer(void*);
void exit_etw(int signal_num);

VOID WINAPI consum_event(PEVENT_RECORD event_pointer);
VOID __cdecl parse_event_multi_thread(void*);