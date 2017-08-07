void setup_event_producer();
VOID WINAPI consum_event(PEVENT_RECORD event_pointer);

VOID __cdecl parse_event_multi_thread(void*);