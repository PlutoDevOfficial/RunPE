# RunPE
PE execution in memory for x86 and x68

# Example Executable

    unsigned char rawData[4379664] = {
    // YOUR EXECUTABLE
    }

# Imports Needed

#include <windows.h>      // Core Windows API functions
#include <winnt.h>        // IMAGE_DOS_HEADER, IMAGE_NT_HEADERS64, IMAGE_SECTION_HEADER
#include <processthreadsapi.h> // PROCESS_INFORMATION, STARTUPINFOA, CONTEXT
#include <memoryapi.h>    // VirtualAllocEx, WriteProcessMemory
#include <debugapi.h>     // GetThreadContext, SetThreadContext
