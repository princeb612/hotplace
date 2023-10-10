/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_BASE_SYSTEM_WINDOWS_SDK_KERNEL32__
#define __HOTPLACE_SDK_BASE_SYSTEM_WINDOWS_SDK_KERNEL32__

#include <tlhelp32.h>

// Interlocked
/* "InterlockedIncrement" */
#define DECLARE_NAMEOF_API_INTERLOCKEDINCREMENT                                                                \
    CHAR NAMEOF_API_INTERLOCKEDINCREMENT[] = {                                                                 \
        'I', 'n', 't', 'e', 'r', 'l', 'o', 'c', 'k', 'e', 'd', 'I', 'n', 'c', 'r', 'e', 'm', 'e', 'n', 't', 0, \
    };
/* "InterlockedDecrement" */
#define DECLARE_NAMEOF_API_INTERLOCKEDDECREMENT                                                                \
    CHAR NAMEOF_API_INTERLOCKEDDECREMENT[] = {                                                                 \
        'I', 'n', 't', 'e', 'r', 'l', 'o', 'c', 'k', 'e', 'd', 'D', 'e', 'c', 'r', 'e', 'm', 'e', 'n', 't', 0, \
    };
/* "InterlockedCompareExchange" */
#define DECLARE_NAMEOF_API_INTERLOCKEDCOMPAREEXCHANGE                                                                                        \
    CHAR NAMEOF_API_INTERLOCKEDCOMPAREEXCHANGE[] = {                                                                                         \
        'I', 'n', 't', 'e', 'r', 'l', 'o', 'c', 'k', 'e', 'd', 'C', 'o', 'm', 'p', 'a', 'r', 'e', 'E', 'x', 'c', 'h', 'a', 'n', 'g', 'e', 0, \
    };
/* "InterlockedExchange" */
#define DECLARE_NAMEOF_API_INTERLOCKEDEXCHANGE                                                            \
    CHAR NAMEOF_API_INTERLOCKEDEXCHANGE[] = {                                                             \
        'I', 'n', 't', 'e', 'r', 'l', 'o', 'c', 'k', 'e', 'd', 'E', 'x', 'c', 'h', 'a', 'n', 'g', 'e', 0, \
    };

/* @brief
    Increments (increases by one) the value of the specified 32-bit variable as an atomic operation.
    To operate on 64-bit values, use the InterlockedIncrement64 function.
 */
typedef LONG(__stdcall *INTERLOCKEDINCREMENT)(__inout LONG volatile *Addend);
/* @brief
    Decrements (decreases by one) the value of the specified 32-bit variable as an atomic operation.
    To operate on 64-bit values, use the InterlockedDecrement64 function.
 */
typedef LONG(__stdcall *INTERLOCKEDDECREMENT)(__inout LONG volatile *Addend);
/* @brief
    Performs an atomic compare-and-exchange operation on the specified values.
    The function compares two specified 32-bit values and exchanges with another 32-bit value based on the outcome of the comparison.
    If you are exchanging pointer values, this function has been superseded by the InterlockedCompareExchangePointer function.
    To operate on 64-bit values, use the InterlockedCompareExchange64 function.
 */
typedef LONG(__stdcall *INTERLOCKEDCOMPAREEXCHANGE)(__inout LONG volatile *Destination, ___in LONG Exchange, ___in LONG Comperand);
/* @brief
    Sets a 32-bit variable to the specified value as an atomic operation.
    To operate on a pointer variable, use the InterlockedExchangePointer function.
    To operate on a 16-bit variable, use the InterlockedExchange16 function.
    To operate on a 64-bit variable, use the InterlockedExchange64 function.
 */
typedef LONG(__stdcall *INTERLOCKEDEXCHANGE)(__inout LONG volatile *Target, ___in LONG Value);

// CriticalSection
/* "InitializeCriticalSectionAndSpinCount" */
#define DECLARE_NAMEOF_API_INITIALIZECRITICALSECTIONANDSPINCOUNT                                       \
    CHAR NAMEOF_API_INITIALIZECRITICALSECTIONANDSPINCOUNT[] = {                                        \
        'I', 'n', 'i', 't', 'i', 'a', 'l', 'i', 'z', 'e', 'C', 'r', 'i', 't', 'i', 'c', 'a', 'l', 'S', \
        'e', 'c', 't', 'i', 'o', 'n', 'A', 'n', 'd', 'S', 'p', 'i', 'n', 'C', 'o', 'u', 'n', 't', 0,   \
    };
/* "TryEnterCriticalSection" */
#define DECLARE_NAMEOF_API_TRYENTERCRITICALSECTION                                                                            \
    CHAR NAMEOF_API_TRYENTERCRITICALSECTION[] = {                                                                             \
        'T', 'r', 'y', 'E', 'n', 't', 'e', 'r', 'C', 'r', 'i', 't', 'i', 'c', 'a', 'l', 'S', 'e', 'c', 't', 'i', 'o', 'n', 0, \
    };

/* @brief
    Initializes a critical section object and sets the spin count for the critical section.
    When a thread tries to acquire a critical section that is locked, the thread spins: it enters a loop which iterates spin count times, checking to see if the
   lock is released. If the lock is not released before the loop finishes, the thread goes to sleep to wait for the lock to be released.
 */
typedef BOOL(__stdcall *INITIALIZECRITICALSECTIONANDSPINCOUNT)(LPCRITICAL_SECTION lpCriticalSection, DWORD dwSpinCount);
/* @brief
    Attempts to enter a critical section without blocking.
    If the call is successful, the calling thread takes ownership of the critical section.
 */
typedef BOOL(__stdcall *TRYENTERCRITICALSECTION)(LPCRITICAL_SECTION lpCriticalSection);

// FindFirstFile/FindNextFile/FindClose
#undef NAMEOF_API_FINDFIRSTFILE
#undef NAMEOF_API_FINDNEXTFILE
#undef FINDFIRSTFILE
#undef FINDNEXTFILE

#if defined _MBCS || defined MBCS
#define DECLARE_NAMEOF_API_FINDFIRSTFILE DECLARE_NAMEOF_API_FINDFIRSTFILEA
#define DECLARE_NAMEOF_API_FINDNEXTFILE DECLARE_NAMEOF_API_FINDNEXTFILEA

#define NAMEOF_API_FINDFIRSTFILE NAMEOF_API_FINDFIRSTFILEA
#define NAMEOF_API_FINDNEXTFILE NAMEOF_API_FINDNEXTFILEA

#define FINDFIRSTFILE FINDFIRSTFILEA
#define FINDNEXTFILE FINDNEXTFILEA
#elif defined _UNICODE || defined UNICODE
#define DECLARE_NAMEOF_API_FINDFIRSTFILE DECLARE_NAMEOF_API_FINDFIRSTFILEW
#define DECLARE_NAMEOF_API_FINDNEXTFILE DECLARE_NAMEOF_API_FINDNEXTFILEW

#define NAMEOF_API_FINDFIRSTFILE NAMEOF_API_FINDFIRSTFILEW
#define NAMEOF_API_FINDNEXTFILE NAMEOF_API_FINDNEXTFILEW

#define FINDFIRSTFILE FINDFIRSTFILEW
#define FINDNEXTFILE FINDNEXTFILEW
#endif

/* "FindFirstFileA" */
#define DECLARE_NAMEOF_API_FINDFIRSTFILEA                                        \
    CHAR NAMEOF_API_FINDFIRSTFILEA[] = {                                         \
        'F', 'i', 'n', 'd', 'F', 'i', 'r', 's', 't', 'F', 'i', 'l', 'e', 'A', 0, \
    };
/* "FindFirstFileW" */
#define DECLARE_NAMEOF_API_FINDFIRSTFILEW                                        \
    CHAR NAMEOF_API_FINDFIRSTFILEW[] = {                                         \
        'F', 'i', 'n', 'd', 'F', 'i', 'r', 's', 't', 'F', 'i', 'l', 'e', 'W', 0, \
    };
/* "FindNextFileA" */
#define DECLARE_NAMEOF_API_FINDNEXTFILEA                                    \
    CHAR NAMEOF_API_FINDNEXTFILEA[] = {                                     \
        'F', 'i', 'n', 'd', 'N', 'e', 'x', 't', 'F', 'i', 'l', 'e', 'A', 0, \
    };
/* "FindNextFileW" */
#define DECLARE_NAMEOF_API_FINDNEXTFILEW                                    \
    CHAR NAMEOF_API_FINDNEXTFILEW[] = {                                     \
        'F', 'i', 'n', 'd', 'N', 'e', 'x', 't', 'F', 'i', 'l', 'e', 'W', 0, \
    };
/* "FindClose" */
#define DECLARE_NAMEOF_API_FINDCLOSE                    \
    CHAR NAMEOF_API_FINDCLOSE[] = {                     \
        'F', 'i', 'n', 'd', 'C', 'l', 'o', 's', 'e', 0, \
    };

/* @brief
    Searches a directory for a file or subdirectory with a name that matches a specific name (or partial name if wildcards are used).
    To specify additional attributes to use in a search, use the FindFirstFileEx function.
    To perform this operation as a transacted operation, use the FindFirstFileTransacted function.
 */
typedef HANDLE(__stdcall *FINDFIRSTFILEA)(___in LPCSTR lpFileName, ___out LPWIN32_FIND_DATAA lpFindFileData);
typedef HANDLE(__stdcall *FINDFIRSTFILEW)(___in LPCWSTR lpFileName, ___out LPWIN32_FIND_DATAW lpFindFileData);
/* @brief
    Continues a file search from a previous call to the FindFirstFile, FindFirstFileEx, or FindFirstFileTransacted functions.
 */
typedef BOOL(__stdcall *FINDNEXTFILEA)(___in HANDLE hFindFile, ___out LPWIN32_FIND_DATAA lpFindFileData);
typedef BOOL(__stdcall *FINDNEXTFILEW)(___in HANDLE hFindFile, ___out LPWIN32_FIND_DATAW lpFindFileData);
/* @brief
    Closes a file search handle opened by the FindFirstFile, FindFirstFileEx, FindFirstFileNameW, FindFirstFileNameTransactedW, FindFirstFileTransacted,
   FindFirstStreamTransactedW, or FindFirstStreamW functions.
 */
typedef BOOL(__stdcall *FINDCLOSE)(__inout HANDLE hFindFile);

// ReadFileEx/WriteFileEx
/* "ReadFileEx" */
#define DECLARE_NAMEOF_API_READFILEEX                        \
    CHAR NAMEOF_API_READFILEEX[] = {                         \
        'R', 'e', 'a', 'd', 'F', 'i', 'l', 'e', 'E', 'x', 0, \
    };
/* "WriteFileEx" */
#define DECLARE_NAMEOF_API_WRITEFILEEX                            \
    CHAR NAMEOF_API_WRITEFILEEX[] = {                             \
        'W', 'r', 'i', 't', 'e', 'F', 'i', 'l', 'e', 'E', 'x', 0, \
    };

/* @brief
    Reads data from the specified file or input/output (I/O) device.
    It reports its completion status asynchronously, calling the specified completion routine when reading is completed or canceled and the calling thread is in
   an alertable wait state. To read data from a file or device synchronously, use the ReadFile function.
 */
typedef BOOL(__stdcall *READFILEEX)(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPOVERLAPPED lpOverlapped,
                                    LPOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);

/* @brief
    Writes data to the specified file or input/output (I/O) device.
    It reports its completion status asynchronously, calling the specified completion routine when writing is completed or canceled and the calling thread is in
   an alertable wait state. To write data to a file or device synchronously, use the WriteFile function.
 */
typedef BOOL(__stdcall *WRITEFILEEX)(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPOVERLAPPED lpOverlapped,
                                     LPOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);

// CreateToolhelp32Snapshot/Process32First/Process32Next/Module32First/Module32Next
/* "CreateToolhelp32Snapshot" */
#define DECLARE_NAMEOF_API_CREATETOOLHELP32SNAPSHOT                                                                                \
    CHAR NAMEOF_API_CREATETOOLHELP32SNAPSHOT[] = {                                                                                 \
        'C', 'r', 'e', 'a', 't', 'e', 'T', 'o', 'o', 'l', 'h', 'e', 'l', 'p', '3', '2', 'S', 'n', 'a', 'p', 's', 'h', 'o', 't', 0, \
    };

/* @brief
    Takes a snapshot of the specified processes, as well as the heaps, modules, and threads used by these processes.
 */
typedef HANDLE(__stdcall *CREATETOOLHELP32SNAPSHOT)(DWORD, DWORD);

#if defined _MBCS || defined MBCS
#define DECLARE_NAMEOF_API_PROCESS32FIRST DECLARE_NAMEOF_API_PROCESS32FIRSTA
#define DECLARE_NAMEOF_API_PROCESS32NEXT DECLARE_NAMEOF_API_PROCESS32NEXTA

#define NAMEOF_API_PROCESS32FIRST NAMEOF_API_PROCESS32FIRSTA
#define NAMEOF_API_PROCESS32NEXT NAMEOF_API_PROCESS32NEXTA
#elif defined _UNICODE || defined UNICODE
#define DECLARE_NAMEOF_API_PROCESS32FIRST DECLARE_NAMEOF_API_PROCESS32FIRSTW
#define DECLARE_NAMEOF_API_PROCESS32NEXT DECLARE_NAMEOF_API_PROCESS32NEXTW

#define NAMEOF_API_PROCESS32FIRST NAMEOF_API_PROCESS32FIRSTW
#define NAMEOF_API_PROCESS32NEXT NAMEOF_API_PROCESS32NEXTW
#endif
/* "Process32First" */
#define DECLARE_NAMEOF_API_PROCESS32FIRSTA                                       \
    CHAR NAMEOF_API_PROCESS32FIRSTA[] = {                                        \
        'P', 'r', 'o', 'c', 'e', 's', 's', '3', '2', 'F', 'i', 'r', 's', 't', 0, \
    };
/* "Process32FirstW" */
#define DECLARE_NAMEOF_API_PROCESS32FIRSTW                                            \
    CHAR NAMEOF_API_PROCESS32FIRSTW[] = {                                             \
        'P', 'r', 'o', 'c', 'e', 's', 's', '3', '2', 'F', 'i', 'r', 's', 't', 'W', 0, \
    };
/* "Process32Next" */
#define DECLARE_NAMEOF_API_PROCESS32NEXTA                                   \
    CHAR NAMEOF_API_PROCESS32NEXTA[] = {                                    \
        'P', 'r', 'o', 'c', 'e', 's', 's', '3', '2', 'N', 'e', 'x', 't', 0, \
    };
/* "Process32NextW" */
#define DECLARE_NAMEOF_API_PROCESS32NEXTW                                        \
    CHAR NAMEOF_API_PROCESS32NEXTW[] = {                                         \
        'P', 'r', 'o', 'c', 'e', 's', 's', '3', '2', 'N', 'e', 'x', 't', 'W', 0, \
    };

/* @brief
    Retrieves information about the first process encountered in a system snapshot.
 */
typedef BOOL(__stdcall *PROCESS32FIRSTA)(HANDLE, LPPROCESSENTRY32);
typedef BOOL(__stdcall *PROCESS32FIRSTW)(HANDLE, LPPROCESSENTRY32W);
/* @brief
    Retrieves information about the next process recorded in a system snapshot.
 */
typedef BOOL(__stdcall *PROCESS32NEXTA)(HANDLE, LPPROCESSENTRY32);
typedef BOOL(__stdcall *PROCESS32NEXTW)(HANDLE, LPPROCESSENTRY32W);

#if defined _MBCS || defined MBCS
#define DECLARE_NAMEOF_API_MODULE32FIRST DECLARE_NAMEOF_API_MODULE32FIRSTA
#define DECLARE_NAMEOF_API_MODULE32NEXT DECLARE_NAMEOF_API_MODULE32NEXTA

#define NAMEOF_API_MODULE32FIRST NAMEOF_API_MODULE32FIRSTA
#define NAMEOF_API_MODULE32NEXT NAMEOF_API_MODULE32NEXTA

#define MODULE32FIRST MODULE32FIRSTA
#define MODULE32NEXT MODULE32NEXTA
#elif defined _UNICODE || defined UNICODE
#define DECLARE_NAMEOF_API_MODULE32FIRST DECLARE_NAMEOF_API_MODULE32FIRSTW
#define DECLARE_NAMEOF_API_MODULE32NEXT DECLARE_NAMEOF_API_MODULE32NEXTW

#define NAMEOF_API_MODULE32FIRST NAMEOF_API_MODULE32FIRSTW
#define NAMEOF_API_MODULE32NEXT NAMEOF_API_MODULE32NEXTW

#define MODULE32FIRST MODULE32FIRSTW
#define MODULE32NEXT MODULE32NEXTW
#endif

/* "Module32First" */
#define DECLARE_NAMEOF_API_MODULE32FIRSTA                                   \
    CHAR NAMEOF_API_MODULE32FIRSTA[] = {                                    \
        'M', 'o', 'd', 'u', 'l', 'e', '3', '2', 'F', 'i', 'r', 's', 't', 0, \
    };
/* "Module32Next" */
#define DECLARE_NAMEOF_API_MODULE32NEXTA                               \
    CHAR NAMEOF_API_MODULE32NEXTA[] = {                                \
        'M', 'o', 'd', 'u', 'l', 'e', '3', '2', 'N', 'e', 'x', 't', 0, \
    };
/* "Module32FirstW" */
#define DECLARE_NAMEOF_API_MODULE32FIRSTW                                        \
    CHAR NAMEOF_API_MODULE32FIRSTW[] = {                                         \
        'M', 'o', 'd', 'u', 'l', 'e', '3', '2', 'F', 'i', 'r', 's', 't', 'W', 0, \
    };
/* "Module32NextW" */
#define DECLARE_NAMEOF_API_MODULE32NEXTW                                    \
    CHAR NAMEOF_API_MODULE32NEXTW[] = {                                     \
        'M', 'o', 'd', 'u', 'l', 'e', '3', '2', 'N', 'e', 'x', 't', 'W', 0, \
    };

/* @brief
    Retrieves information about the first module associated with a process.
 */
typedef BOOL(__stdcall *MODULE32FIRSTA)(HANDLE hSnapshot, LPMODULEENTRY32 lpme);
typedef BOOL(__stdcall *MODULE32FIRSTW)(HANDLE hSnapshot, LPMODULEENTRY32W lpme);

/* @brief
    Retrieves information about the next module associated with a process or thread.
 */
typedef BOOL(__stdcall *MODULE32NEXTA)(HANDLE hSnapshot, LPMODULEENTRY32 lpme);
typedef BOOL(__stdcall *MODULE32NEXTW)(HANDLE hSnapshot, LPMODULEENTRY32W lpme);

// OutputDebugString

#undef NAMEOF_API_OUTPUTDEBUGSTRING

/* "OutputDebugStringA" */
#define DECLARE_NAMEOF_API_OUTPUTDEBUGSTRINGA                                                        \
    CHAR NAMEOF_API_OUTPUTDEBUGSTRINGA[] = {                                                         \
        'O', 'u', 't', 'p', 'u', 't', 'D', 'e', 'b', 'u', 'g', 'S', 't', 'r', 'i', 'n', 'g', 'A', 0, \
    };
/* "OutputDebugStringW" */
#define DECLARE_NAMEOF_API_OUTPUTDEBUGSTRINGW                                                        \
    CHAR NAMEOF_API_OUTPUTDEBUGSTRINGW[] = {                                                         \
        'O', 'u', 't', 'p', 'u', 't', 'D', 'e', 'b', 'u', 'g', 'S', 't', 'r', 'i', 'n', 'g', 'W', 0, \
    };

#if defined _MBCS || defined MBCS
#define DECLARE_NAMEOF_API_OUTPUTDEBUGSTRING DECLARE_NAMEOF_API_OUTPUTDEBUGSTRINGA

#define NAMEOF_API_OUTPUTDEBUGSTRING NAMEOF_API_OUTPUTDEBUGSTRINGA
#elif defined _UNICODE || defined UNICODE
#define DECLARE_NAMEOF_API_OUTPUTDEBUGSTRING DECLARE_NAMEOF_API_OUTPUTDEBUGSTRINGW

#define NAMEOF_API_OUTPUTDEBUGSTRING NAMEOF_API_OUTPUTDEBUGSTRINGW
#endif

/* @brief
    Sends a string to the debugger for display.
 */
typedef VOID(__stdcall *OUTPUTDEBUGSTRINGA)(__in_opt LPCSTR lpOutputString);
typedef VOID(__stdcall *OUTPUTDEBUGSTRINGW)(__in_opt LPCWSTR lpOutputString);

/* FormatMessage */
#define DECLARE_NAMEOF_API_FORMATMESSAGEA                                        \
    CHAR NAMEOF_API_FORMATMESSAGEA[] = {                                         \
        'F', 'o', 'r', 'm', 'a', 't', 'M', 'e', 's', 's', 'a', 'g', 'e', 'A', 0, \
    };
#define DECLARE_NAMEOF_API_FORMATMESSAGEW                                        \
    CHAR NAMEOF_API_FORMATMESSAGEW[] = {                                         \
        'F', 'o', 'r', 'm', 'a', 't', 'M', 'e', 's', 's', 'a', 'g', 'e', 'W', 0, \
    };

/* @brief
    Formats a message string.
    The function requires a message definition as input.
    The message definition can come from a buffer passed into the function.
    It can come from a message table resource in an already-loaded module.
    Or the caller can ask the function to search the system's message table resource(s) for the message definition.
    The function finds the message definition in a message table resource based on a message identifier and a language identifier.
    The function copies the formatted message text to an output buffer, processing any embedded insert sequences if requested.
 */
typedef DWORD(__stdcall *FORMATMESSAGEA)(___in DWORD dwFlags, __in_opt LPCVOID lpSource, ___in DWORD dwMessageId, ___in DWORD dwLanguageId,
                                         ___out LPSTR lpBuffer, ___in DWORD nSize, __in_opt va_list *Arguments);
typedef DWORD(__stdcall *FORMATMESSAGEW)(___in DWORD dwFlags, __in_opt LPCVOID lpSource, ___in DWORD dwMessageId, ___in DWORD dwLanguageId,
                                         ___out LPWSTR lpBuffer, ___in DWORD nSize, __in_opt va_list *Arguments);

/* "GetNativeSystemInfo" */
#define DECLARE_NAMEOF_API_GETNATIVESYSTEMINFO                                                            \
    CHAR NAMEOF_API_GETNATIVESYSTEMINFO[] = {                                                             \
        'G', 'e', 't', 'N', 'a', 't', 'i', 'v', 'e', 'S', 'y', 's', 't', 'e', 'm', 'I', 'n', 'f', 'o', 0, \
    };

/* @brief
    Retrieves information about the current system to an application running under WOW64.
    If the function is called from a 64-bit application, it is equivalent to the GetSystemInfo function.
 */
typedef void(__stdcall *GETNATIVESYSTEMINFO)(LPSYSTEM_INFO lpSystemInfo);

/* "GetUserDefaultUILanguage" */
#define DECLARE_NAMEOF_API_GETUSERDEFAULTUILANGUAGE                                                                                \
    CHAR NAMEOF_API_GETUSERDEFAULTUILANGUAGE[] = {                                                                                 \
        'G', 'e', 't', 'U', 's', 'e', 'r', 'D', 'e', 'f', 'a', 'u', 'l', 't', 'U', 'I', 'L', 'a', 'n', 'g', 'u', 'a', 'g', 'e', 0, \
    };

/* @brief
    Returns the language identifier for the user UI language for the current user.
    If the current user has not set a language, GetUserDefaultUILanguage returns the preferred language set for the system.
    If there is no preferred language set for the system, then the system default UI language (also known as "install language") is returned.
    For more information about the user UI language, see User Interface Language Management.
 */
typedef LANGID(__stdcall FAR *GETUSERDEFAULTUILANGUAGE)(void);

#if defined __MINGW32__

#if defined UNICODE
#define OSVERSIONINFOEX OSVERSIONINFOEXW
#else
#define OSVERSIONINFOEX OSVERSIONINFOEXA
#endif

#endif

#undef NAMEOF_API_VERIFYVERSIONINFO

#if defined _MBCS || defined MBCS
#define DECLARE_NAMEOF_API_VERIFYVERSIONINFO DECLARE_NAMEOF_API_VERIFYVERSIONINFOA

#define NAMEOF_API_VERIFYVERSIONINFO NAMEOF_API_VERIFYVERSIONINFOA
#elif defined _UNICODE || defined UNICODE
#define DECLARE_NAMEOF_API_VERIFYVERSIONINFO DECLARE_NAMEOF_API_VERIFYVERSIONINFOW

#define NAMEOF_API_VERIFYVERSIONINFO NAMEOF_API_VERIFYVERSIONINFOW
#endif

/* "VerifyVersionInfoA" */
#define DECLARE_NAMEOF_API_VERIFYVERSIONINFOA                                                        \
    CHAR NAMEOF_API_VERIFYVERSIONINFOA[] = {                                                         \
        'V', 'e', 'r', 'i', 'f', 'y', 'V', 'e', 'r', 's', 'i', 'o', 'n', 'I', 'n', 'f', 'o', 'A', 0, \
    };
/* "VerifyVersionInfoW" */
#define DECLARE_NAMEOF_API_VERIFYVERSIONINFOW                                                        \
    CHAR NAMEOF_API_VERIFYVERSIONINFOW[] = {                                                         \
        'V', 'e', 'r', 'i', 'f', 'y', 'V', 'e', 'r', 's', 'i', 'o', 'n', 'I', 'n', 'f', 'o', 'W', 0, \
    };

/* @brief
    Compares a set of operating system version requirements to the corresponding values for the currently running version of the system.
 */
typedef BOOL(NTAPI *VERIFYVERSIONINFO)(POSVERSIONINFOEX, DWORD, DWORDLONG);

/* "GetProductInfo" */
#define DECLARE_NAMEOF_API_GETPRODUCTINFO                                        \
    CHAR NAMEOF_API_GETPRODUCTINFO[] = {                                         \
        'G', 'e', 't', 'P', 'r', 'o', 'd', 'u', 'c', 't', 'I', 'n', 'f', 'o', 0, \
    };
/* @brief
    Retrieves the product type for the operating system on the local computer, and maps the type to the product types supported by the specified operating
   system. To retrieve product type information on versions of Windows prior to the minimum supported operating systems specified in the Requirements section,
   use the GetVersionEx function. You can also use the OperatingSystemSKU property of the Win32_OperatingSystem WMI class.
   @comment
    Vista Edition 을 파악하기 위해서 GetProductInfo API 를 이용한다.
    see alse, http://msdn2.microsoft.com/en-gb/library/ms724358.aspx
 */
typedef BOOL(__stdcall *GETPRODUCTINFO)(DWORD, DWORD, DWORD, DWORD, LPDWORD);

/* "GetProcessWorkingSetSize" */
#define DECLARE_NAMEOF_API_GETPROCESSWORKINGSETSIZE                                                                                \
    CHAR NAMEOF_API_GETPROCESSWORKINGSETSIZE[] = {                                                                                 \
        'G', 'e', 't', 'P', 'r', 'o', 'c', 'e', 's', 's', 'W', 'o', 'r', 'k', 'i', 'n', 'g', 'S', 'e', 't', 'S', 'i', 'z', 'e', 0, \
    };

/* @brief
    Retrieves the minimum and maximum working set sizes of the specified process.
 */
typedef BOOL(__stdcall *GETPROCESSWORKINGSETSIZE)(___in HANDLE hProcess, ___out PSIZE_T lpMinimumWorkingSetSize, ___out PSIZE_T lpMaximumWorkingSetSize);

/* "SetProcessWorkingSetSize" */
#define DECLARE_NAMEOF_API_SETPROCESSWORKINGSETSIZE                                                                                \
    CHAR NAMEOF_API_SETPROCESSWORKINGSETSIZE[] = {                                                                                 \
        'S', 'e', 't', 'P', 'r', 'o', 'c', 'e', 's', 's', 'W', 'o', 'r', 'k', 'i', 'n', 'g', 'S', 'e', 't', 'S', 'i', 'z', 'e', 0, \
    };

/* @brief
    Sets the minimum and maximum working set sizes for the specified process.
 */
typedef BOOL(__stdcall *SETPROCESSWORKINGSETSIZE)(___in HANDLE hProcess, ___in SIZE_T dwMinimumWorkingSetSize, ___in SIZE_T dwMaximumWorkingSetSize);

#undef NAMEOF_API_GETSYSTEMWOW64DIRECTORY

#if defined _MBCS || defined MBCS
#define DECLARE_NAMEOF_API_GETSYSTEMWOW64DIRECTORY DECLARE_NAMEOF_API_GETSYSTEMWOW64DIRECTORYA

#define NAMEOF_API_GETSYSTEMWOW64DIRECTORY NAMEOF_API_GETSYSTEMWOW64DIRECTORYA

#define GETSYSTEMWOW64DIRECTORY GETSYSTEMWOW64DIRECTORYA
#elif defined _UNICODE || defined UNICODE
#define DECLARE_NAMEOF_API_GETSYSTEMWOW64DIRECTORY DECLARE_NAMEOF_API_GETSYSTEMWOW64DIRECTORYW

#define NAMEOF_API_GETSYSTEMWOW64DIRECTORY NAMEOF_API_GETSYSTEMWOW64DIRECTORYW

#define GETSYSTEMWOW64DIRECTORY GETSYSTEMWOW64DIRECTORYW
#endif

/* "GetSystemWow64DirectoryA" */
#define DECLARE_NAMEOF_API_GETSYSTEMWOW64DIRECTORYA                                                                                \
    CHAR NAMEOF_API_GETSYSTEMWOW64DIRECTORYA[] = {                                                                                 \
        'G', 'e', 't', 'S', 'y', 's', 't', 'e', 'm', 'W', 'o', 'w', '6', '4', 'D', 'i', 'r', 'e', 'c', 't', 'o', 'r', 'y', 'A', 0, \
    };
/* "GetSystemWow64DirectoryW" */
#define DECLARE_NAMEOF_API_GETSYSTEMWOW64DIRECTORYW                                                                                \
    CHAR NAMEOF_API_GETSYSTEMWOW64DIRECTORYW[] = {                                                                                 \
        'G', 'e', 't', 'S', 'y', 's', 't', 'e', 'm', 'W', 'o', 'w', '6', '4', 'D', 'i', 'r', 'e', 'c', 't', 'o', 'r', 'y', 'W', 0, \
    };

/* @brief
    Retrieves the path of the system directory used by WOW64.
    This directory is not present on 32-bit Windows.
 */
typedef UINT(__stdcall *GETSYSTEMWOW64DIRECTORYA)(LPSTR lpBuffer, UINT uSize);
typedef UINT(__stdcall *GETSYSTEMWOW64DIRECTORYW)(LPWSTR lpBuffer, UINT uSize);

/* "SetSystemPowerState" */
#define DECLARE_NAMEOF_API_SETSYSTEMPOWERSTATE                                                            \
    CHAR NAMEOF_API_SETSYSTEMPOWERSTATE[] = {                                                             \
        'S', 'e', 't', 'S', 'y', 's', 't', 'e', 'm', 'P', 'o', 'w', 'e', 'r', 'S', 't', 'a', 't', 'e', 0, \
    };

/* @brief
    [SetSystemPowerState is available for use in the operating systems specified in the Requirements section.
    It may be altered or unavailable in subsequent versions. Applications written for Windows Vista and later should use SetSuspendState instead.]

    Suspends the system by shutting power down. Depending on the ForceFlag parameter, the function either suspends operation immediately or requests permission
   from all applications and device drivers before doing so.
   @comment
    see SystemHalt
 */
typedef BOOL(__stdcall *SETSYSTEMPOWERSTATE)(___in BOOL fSuspend, ___in BOOL fForce);

/* "GetSystemPowerStatus" */
#define DECLARE_NAMEOF_API_GETSYSTEMPOWERSTATUS                                                                \
    CHAR NAMEOF_API_GETSYSTEMPOWERSTATUS[] = {                                                                 \
        'G', 'e', 't', 'S', 'y', 's', 't', 'e', 'm', 'P', 'o', 'w', 'e', 'r', 'S', 't', 'a', 't', 'u', 's', 0, \
    };

/* @brief
    Retrieves the power status of the system.
    The status indicates whether the system is running on AC or DC power, whether the battery is currently charging, and how much battery life remains.
 */
typedef BOOL(__stdcall *GETSYSTEMPOWERSTATUS)(___out LPSYSTEM_POWER_STATUS lpSystemPowerStatus);

#undef NAMEOF_API_CREATEJOBOBJECT

#if defined _MBCS || defined MBCS
#define DECLARE_NAMEOF_API_CREATEJOBOBJECT DECLARE_NAMEOF_API_CREATEJOBOBJECTA

#define NAMEOF_API_CREATEJOBOBJECT NAMEOF_API_CREATEJOBOBJECTA
#elif defined _UNICODE || defined UNICODE
#define DECLARE_NAMEOF_API_CREATEJOBOBJECT DECLARE_NAMEOF_API_CREATEJOBOBJECTW

#define NAMEOF_API_CREATEJOBOBJECT NAMEOF_API_CREATEJOBOBJECTW
#endif

/* "CreateJobObjectA" */
#define DECLARE_NAMEOF_API_CREATEJOBOBJECTA                                                \
    CHAR NAMEOF_API_CREATEJOBOBJECTA[] = {                                                 \
        'C', 'r', 'e', 'a', 't', 'e', 'J', 'o', 'b', 'O', 'b', 'j', 'e', 'c', 't', 'A', 0, \
    };
/* "CreateJobObjectW" */
#define DECLARE_NAMEOF_API_CREATEJOBOBJECTW                                                \
    CHAR NAMEOF_API_CREATEJOBOBJECTW[] = {                                                 \
        'C', 'r', 'e', 'a', 't', 'e', 'J', 'o', 'b', 'O', 'b', 'j', 'e', 'c', 't', 'W', 0, \
    };

/* @brief
    Creates or opens a job object.
 */
typedef HANDLE(__stdcall *CREATEJOBOBJECTA)(__in_opt LPSECURITY_ATTRIBUTES lpJobAttributes, __in_opt LPCSTR lpName);
typedef HANDLE(__stdcall *CREATEJOBOBJECTW)(__in_opt LPSECURITY_ATTRIBUTES lpJobAttributes, __in_opt LPCWSTR lpName);

/* "AssignProcessToJobObject" */
#define DECLARE_NAMEOF_API_ASSIGNPROCESSTOJOBOBJECT                                                                                \
    CHAR NAMEOF_API_ASSIGNPROCESSTOJOBOBJECT[] = {                                                                                 \
        'A', 's', 's', 'i', 'g', 'n', 'P', 'r', 'o', 'c', 'e', 's', 's', 'T', 'o', 'J', 'o', 'b', 'O', 'b', 'j', 'e', 'c', 't', 0, \
    };

/* @brief
    Assigns a process to an existing job object.
 */
typedef BOOL(__stdcall *ASSIGNPROCESSTOJOBOBJECT)(___in HANDLE hJob, ___in HANDLE hProcess);

/* "TerminateJobObject" */
#define DECLARE_NAMEOF_API_TERMINATEJOBOBJECT                                                        \
    CHAR NAMEOF_API_TERMINATEJOBOBJECT[] = {                                                         \
        'T', 'e', 'r', 'm', 'i', 'n', 'a', 't', 'e', 'J', 'o', 'b', 'O', 'b', 'j', 'e', 'c', 't', 0, \
    };

/* @brief
    Terminates all processes currently associated with the job.
    If the job is nested, this function terminates all processes currently associated with the job and all of its child jobs in the hierarchy.
 */
typedef BOOL(__stdcall *TERMINATEJOBOBJECT)(___in HANDLE hJob, ___in UINT uExitCode);

/* "ProcessIdToSessionId" */
#define DECLARE_NAMEOF_API_PROCESSIDTOSESSIONID                                                                \
    CHAR NAMEOF_API_PROCESSIDTOSESSIONID[] = {                                                                 \
        'P', 'r', 'o', 'c', 'e', 's', 's', 'I', 'd', 'T', 'o', 'S', 'e', 's', 's', 'i', 'o', 'n', 'I', 'd', 0, \
    };

/* @brief
    Retrieves the Remote Desktop Services session associated with a specified process.
 */
typedef BOOL(__stdcall *PROCESSIDTOSESSIONID)(DWORD dwProcessId, DWORD *pSessionId);

/* "WTSGetActiveConsoleSessionId" */
#define DECLARE_NAMEOF_API_WTSGETACTIVECONSOLESESSIONID                                                                                                \
    CHAR NAMEOF_API_WTSGETACTIVECONSOLESESSIONID[] = {                                                                                                 \
        'W', 'T', 'S', 'G', 'e', 't', 'A', 'c', 't', 'i', 'v', 'e', 'C', 'o', 'n', 's', 'o', 'l', 'e', 'S', 'e', 's', 's', 'i', 'o', 'n', 'I', 'd', 0, \
    };

/* @brief
    Retrieves the Remote Desktop Services session that is currently attached to the physical console.
    The physical console is the monitor, keyboard, and mouse.
    Note that it is not necessary that Remote Desktop Services be running for this function to succeed.
 */
typedef DWORD(__stdcall *WTSGETACTIVECONSOLESESSIONID)();

/* "IsWow64Process" */
#define DECLARE_NAMEOF_API_ISWOW64PROCESS                                        \
    CHAR NAMEOF_API_ISWOW64PROCESS[] = {                                         \
        'I', 's', 'W', 'o', 'w', '6', '4', 'P', 'r', 'o', 'c', 'e', 's', 's', 0, \
    };

/* @brief
    Determines whether the specified process is running under WOW64.
 */
typedef BOOL(__stdcall *ISWOW64PROCESS)(HANDLE, PBOOL);

/* "Wow64EnableWow64FsRedirection" */
#define DECLARE_NAMEOF_API_WOW64ENABLEWOW64FSREDIRECTION                                                                                                    \
    CHAR NAMEOF_API_WOW64ENABLEWOW64FSREDIRECTION[] = {                                                                                                     \
        'W', 'o', 'w', '6', '4', 'E', 'n', 'a', 'b', 'l', 'e', 'W', 'o', 'w', '6', '4', 'F', 's', 'R', 'e', 'd', 'i', 'r', 'e', 'c', 't', 'i', 'o', 'n', 0, \
    };
/* "Wow64DisableWow64FsRedirection" */
#define DECLARE_NAMEOF_API_WOW64DISABLEWOW64FSREDIRECTION                                   \
    CHAR NAMEOF_API_WOW64DISABLEWOW64FSREDIRECTION[] =                                      \
        {                                                                                   \
            'W', 'o', 'w', '6', '4', 'D', 'i', 's', 'a', 'b', 'l', 'e', 'W', 'o', 'w', '6', \
            '4', 'F', 's', 'R', 'e', 'd', 'i', 'r', 'e', 'c', 't', 'i', 'o', 'n', 0,        \
    };
/* "Wow64RevertWow64FsRedirection" */
#define DECLARE_NAMEOF_API_WOW64REVERTWOW64FSREDIRECTION                                                                                                    \
    CHAR NAMEOF_API_WOW64REVERTWOW64FSREDIRECTION[] = {                                                                                                     \
        'W', 'o', 'w', '6', '4', 'R', 'e', 'v', 'e', 'r', 't', 'W', 'o', 'w', '6', '4', 'F', 's', 'R', 'e', 'd', 'i', 'r', 'e', 'c', 't', 'i', 'o', 'n', 0, \
    };

/* @brief
    Enables or disables file system redirection for the calling thread.
    This function may not work reliably when there are nested calls.
    Therefore, this function has been replaced by the Wow64DisableWow64FsRedirection and Wow64RevertWow64FsRedirection functions.
    Note  These two methods of controlling file system redirection cannot be combined in any way.
    Do not use the Wow64EnableWow64FsRedirection function with either the Wow64DisableWow64FsRedirection or the Wow64RevertWow64FsRedirection function.
 */
typedef BOOLEAN(__stdcall *WOW64ENABLEWOW64FSREDIRECTION)(BOOLEAN Wow64FsEnableRedirection);
/* @brief
    Disables file system redirection for the calling thread. File system redirection is enabled by default.
 */
typedef BOOL(__stdcall *WOW64DISABLEWOW64FSREDIRECTION)(PVOID *OldValue);
/* @brief
    Restores file system redirection for the calling thread.
    This function should not be called without a previous call to the Wow64DisableWow64FsRedirection function.
    Any data allocation on behalf of the Wow64DisableWow64FsRedirection function is cleaned up by this function.
 */
typedef BOOL(__stdcall *WOW64REVERTWOW64FSREDIRECTION)(PVOID OlValue);

/* fiber */

typedef VOID(__stdcall *PFIBER_START_ROUTINE)(LPVOID lpFiberParameter);
typedef PFIBER_START_ROUTINE LPFIBER_START_ROUTINE;

/* "CreateFiber" */
#define DECLARE_NAMEOF_API_CREATEFIBER                            \
    CHAR NAMEOF_API_CREATEFIBER[] = {                             \
        'C', 'r', 'e', 'a', 't', 'e', 'F', 'i', 'b', 'e', 'r', 0, \
    };
/* "DeleteFiber" */
#define DECLARE_NAMEOF_API_DELETEFIBER                            \
    CHAR NAMEOF_API_DELETEFIBER[] = {                             \
        'D', 'e', 'l', 'e', 't', 'e', 'F', 'i', 'b', 'e', 'r', 0, \
    };
/* "SwitchToFiber" */
#define DECLARE_NAMEOF_API_SWITCHTOFIBER                                    \
    CHAR NAMEOF_API_SWITCHTOFIBER[] = {                                     \
        'S', 'w', 'i', 't', 'c', 'h', 'T', 'o', 'F', 'i', 'b', 'e', 'r', 0, \
    };
/* "ConvertThreadToFiber" */
#define DECLARE_NAMEOF_API_CONVERTTHREADTOFIBER                                                                \
    CHAR NAMEOF_API_CONVERTTHREADTOFIBER[] = {                                                                 \
        'C', 'o', 'n', 'v', 'e', 'r', 't', 'T', 'h', 'r', 'e', 'a', 'd', 'T', 'o', 'F', 'i', 'b', 'e', 'r', 0, \
    };
/* "ConvertFiberToThread" */
#define DECLARE_NAMEOF_API_CONVERTFIBERTOTHREAD                                                                \
    CHAR NAMEOF_API_CONVERTFIBERTOTHREAD[] = {                                                                 \
        'C', 'o', 'n', 'v', 'e', 'r', 't', 'F', 'i', 'b', 'e', 'r', 'T', 'o', 'T', 'h', 'r', 'e', 'a', 'd', 0, \
    };

/* @brief
    Allocates a fiber object, assigns it a stack, and sets up execution to begin at the specified start address, typically the fiber function.
    This function does not schedule the fiber.
    To specify both a commit and reserve stack size, use the CreateFiberEx function.
 */
typedef LPVOID(__stdcall *CREATEFIBER)(___in SIZE_T dwStackSize, ___in LPFIBER_START_ROUTINE lpStartAddress, __in_opt LPVOID lpParameter);

/* @brief
    Deletes an existing fiber.
 */
typedef VOID(__stdcall *DELETEFIBER)(___in LPVOID lpFiber);
/* @brief
    Schedules a fiber. The function must be called on a fiber.
 */
typedef VOID(__stdcall *SWITCHTOFIBER)(___in LPVOID lpFiber);
/* @brief
    Converts the current thread into a fiber. You must convert a thread into a fiber before you can schedule other fibers.
 */
typedef LPVOID(__stdcall *CONVERTTHREADTOFIBER)(__in_opt LPVOID lpParameter);
/* @brief
    Converts the current fiber into a thread.
 */
typedef BOOL(__stdcall *CONVERTFIBERTOTHREAD)(VOID);

/* "SwitchToThread" */
#define DECLARE_NAMEOF_API_SWITCHTOTHREAD                                        \
    CHAR NAMEOF_API_SWITCHTOTHREAD[] = {                                         \
        'S', 'w', 'i', 't', 'c', 'h', 'T', 'o', 'T', 'h', 'r', 'e', 'a', 'd', 0, \
    };
/* @brief
    Causes the calling thread to yield execution to another thread that is ready to run on the current processor. The operating system selects the next thread
   to be executed.
 */
typedef BOOL(__stdcall *SWITCHTOTHREAD)(void);
/* @brief
    Allocates a block of memory from a heap. The allocated memory is not movable.
 */
typedef LPVOID(__stdcall *HEAPALLOC)(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
/* @brief
    Frees a memory block allocated from a heap by the HeapAlloc or HeapReAlloc function.
 */
typedef BOOL(__stdcall *HEAPFREE)(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem);
/* @brief
    Allocates the specified number of bytes from the heap.

    Note
    The local functions have greater overhead and provide fewer features than other memory management functions.
    New applications should use the heap functions unless documentation states that a local function should be used.
    For more information, see Global and Local Functions.
 */
typedef HLOCAL(__stdcall *LOCALALLOC)(UINT uFlags, SIZE_T uBytes);
/* @brief
    Frees the specified local memory object and invalidates its handle.

    Note
    The local functions have greater overhead and provide fewer features than other memory management functions.
    New applications should use the heap functions unless documentation states that a local function should be used.
    For more information, see Global and Local Functions.
 */
typedef HLOCAL(__stdcall *LOCALFREE)(HLOCAL hMem);
/* @brief
    Allocates the specified number of bytes from the heap.

    Note
    The global functions have greater overhead and provide fewer features than other memory management functions.
    New applications should use the heap functions unless documentation states that a global function should be used.
    For more information, see Global and Local Functions.
 */
typedef HGLOBAL(__stdcall *GLOBALALLOC)(UINT uFlags, SIZE_T dwBytes);
/* @brief
    Frees the specified global memory object and invalidates its handle.

    Note
    The global functions have greater overhead and provide fewer features than other memory management functions.
    New applications should use the heap functions unless documentation states that a global function should be used.
    For more information, see Global and Local Functions.
 */
typedef HGLOBAL(__stdcall *GLOBALFREE)(HGLOBAL hMem);
/* @brief
    Reserves or commits a region of pages in the virtual address space of the calling process.
    Memory allocated by this function is automatically initialized to zero, unless MEM_RESET is specified.
    To allocate memory in the address space of another process, use the VirtualAllocEx function.
 */
typedef LPVOID(__stdcall *VIRTUALALLOC)(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
/* @brief
    Releases, decommits, or releases and decommits a region of pages within the virtual address space of the calling process.
    To free memory allocated in another process by the VirtualAllocEx function, use the VirtualFreeEx function.
 */
typedef BOOL(__stdcall *VIRTUALFREE)(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType);

/* "DuplicateHandle" */
#define DECLARE_NAMEOF_API_DUPLICATEHANDLE                                            \
    CHAR NAMEOF_API_DUPLICATEHANDLE[] = {                                             \
        'D', 'u', 'p', 'l', 'i', 'c', 'a', 't', 'e', 'H', 'a', 'n', 'd', 'l', 'e', 0, \
    };

/* @brief
    Duplicates an object handle.
 */
typedef BOOL(__stdcall *DUPLICATEHANDLE)(___in HANDLE hSourceProcessHandle, ___in HANDLE hSourceHandle, ___in HANDLE hTargetProcessHandle,
                                         __deref_out LPHANDLE lpTargetHandle, ___in DWORD dwDesiredAccess, ___in BOOL bInheritHandle, ___in DWORD dwOptions);

/* "GetSystemTimes" */
#define DECLARE_NAMEOF_API_GETSYSTEMTIMES                                        \
    CHAR NAMEOF_API_GETSYSTEMTIMES[] = {                                         \
        'G', 'e', 't', 'S', 'y', 's', 't', 'e', 'm', 'T', 'i', 'm', 'e', 's', 0, \
    };
/* "GetProcessTimes" */
#define DECLARE_NAMEOF_API_GETPROCESSTIMES                                            \
    CHAR NAMEOF_API_GETPROCESSTIMES[] = {                                             \
        'G', 'e', 't', 'P', 'r', 'o', 'c', 'e', 's', 's', 'T', 'i', 'm', 'e', 's', 0, \
    };

/* @brief
    Retrieves system timing information.
    On a multiprocessor system, the values returned are the sum of the designated times across all processors.
 */
typedef BOOL(__stdcall *GETSYSTEMTIMES)(__out_opt LPFILETIME lpIdleTime, __out_opt LPFILETIME lpKernelTime, __out_opt LPFILETIME lpUserTime);

/* @brief
    Retrieves timing information for the specified process.
 */
typedef BOOL(__stdcall *GETPROCESSTIMES)(___in HANDLE hProcess, ___out LPFILETIME lpCreationTime, ___out LPFILETIME lpExitTime, ___out LPFILETIME lpKernelTime,
                                         ___out LPFILETIME lpUserTime);

/* "GlobalMemoryStatusEx" */
#define DECLARE_NAMEOF_API_GLOBALMEMORYSTATUSEX                                                                \
    CHAR NAMEOF_API_GLOBALMEMORYSTATUSEX[] = {                                                                 \
        'G', 'l', 'o', 'b', 'a', 'l', 'M', 'e', 'm', 'o', 'r', 'y', 'S', 't', 'a', 't', 'u', 's', 'E', 'x', 0, \
    };

/* @brief
    Retrieves information about the system's current usage of both physical and virtual memory.
 */
typedef BOOL(__stdcall *GLOBALMEMORYSTATUSEX)(LPMEMORYSTATUSEX lpBuffer);
/* "ReadDirectoryChangesW" */
#define DECLARE_NAMEOF_API_READDIRECTORYCHANGESW                                                                    \
    CHAR NAMEOF_API_READDIRECTORYCHANGESW[] = {                                                                     \
        'R', 'e', 'a', 'd', 'D', 'i', 'r', 'e', 'c', 't', 'o', 'r', 'y', 'C', 'h', 'a', 'n', 'g', 'e', 's', 'W', 0, \
    };

/* @brief
    Retrieves information that describes the changes within the specified directory.
    The function does not report changes to the specified directory itself.
    To track changes on a volume, see change journals.
 */
typedef BOOL(__stdcall *READDIRECTORYCHANGESW)(___in HANDLE hDirectory, ___out LPVOID lpBuffer, ___in DWORD nBufferLength, ___in BOOL bWatchSubtree,
                                               ___in DWORD dwNotifyFilter, __out_opt LPDWORD lpBytesReturned, __inout_opt LPOVERLAPPED lpOverlapped,
                                               __in_opt LPOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);

#if defined _MBCS || defined MBCS
#define DECLARE_NAMEOF_API_GETVOLUMENAMEFORVOLUMEMOUNTPOINT DECLARE_NAMEOF_API_GETVOLUMENAMEFORVOLUMEMOUNTPOINTA

#define NAMEOF_API_GETVOLUMENAMEFORVOLUMEMOUNTPOINT NAMEOF_API_GETVOLUMENAMEFORVOLUMEMOUNTPOINTA
#define GETVOLUMENAMEFORVOLUMEMOUNTPOINT GETVOLUMENAMEFORVOLUMEMOUNTPOINTA
#elif defined _UNICODE || defined UNICODE
#define DECLARE_NAMEOF_API_GETVOLUMENAMEFORVOLUMEMOUNTPOINT DECLARE_NAMEOF_API_GETVOLUMENAMEFORVOLUMEMOUNTPOINTW

#define NAMEOF_API_GETVOLUMENAMEFORVOLUMEMOUNTPOINT NAMEOF_API_GETVOLUMENAMEFORVOLUMEMOUNTPOINTW
#define GETVOLUMENAMEFORVOLUMEMOUNTPOINT GETVOLUMENAMEFORVOLUMEMOUNTPOINTW
#endif

/* "GetVolumeNameForVolumeMountPointA" */
#define DECLARE_NAMEOF_API_GETVOLUMENAMEFORVOLUMEMOUNTPOINTA                                 \
    CHAR NAMEOF_API_GETVOLUMENAMEFORVOLUMEMOUNTPOINTA[] = {                                  \
        'G', 'e', 't', 'V', 'o', 'l', 'u', 'm', 'e', 'N', 'a', 'm', 'e', 'F', 'o', 'r', 'V', \
        'o', 'l', 'u', 'm', 'e', 'M', 'o', 'u', 'n', 't', 'P', 'o', 'i', 'n', 't', 'A', 0,   \
    };
/* "GetVolumeNameForVolumeMountPointW" */
#define DECLARE_NAMEOF_API_GETVOLUMENAMEFORVOLUMEMOUNTPOINTW                                 \
    CHAR NAMEOF_API_GETVOLUMENAMEFORVOLUMEMOUNTPOINTW[] = {                                  \
        'G', 'e', 't', 'V', 'o', 'l', 'u', 'm', 'e', 'N', 'a', 'm', 'e', 'F', 'o', 'r', 'V', \
        'o', 'l', 'u', 'm', 'e', 'M', 'o', 'u', 'n', 't', 'P', 'o', 'i', 'n', 't', 'W', 0,   \
    };

/* @brief
    Retrieves a volume GUID path for the volume that is associated with the specified volume mount point ( drive letter, volume GUID path, or mounted folder).
 */
typedef BOOL(__stdcall *GETVOLUMENAMEFORVOLUMEMOUNTPOINTA)(___in LPCSTR lpszVolumeMountPoint, __out_ecount(cchBufferLength) LPSTR lpszVolumeName,
                                                           ___in DWORD cchBufferLength);
/* @brief
 */
typedef BOOL(__stdcall *GETVOLUMENAMEFORVOLUMEMOUNTPOINTW)(___in LPCWSTR lpszVolumeMountPoint, __out_ecount(cchBufferLength) LPWSTR lpszVolumeName,
                                                           ___in DWORD cchBufferLength);

#if defined _MBCS || defined MBCS
#define DECLARE_NAMEOF_API_QUERYDOSDEVICE DECLARE_NAMEOF_API_QUERYDOSDEVICEA

#define NAMEOF_API_QUERYDOSDEVICE NAMEOF_API_QUERYDOSDEVICEA
#define QUERYDOSDEVICE QUERYDOSDEVICEA
#elif defined _UNICODE || defined UNICODE
#define DECLARE_NAMEOF_API_QUERYDOSDEVICE DECLARE_NAMEOF_API_QUERYDOSDEVICEW

#define NAMEOF_API_QUERYDOSDEVICE NAMEOF_API_QUERYDOSDEVICEW
#define QUERYDOSDEVICE QUERYDOSDEVICEW
#endif

/* "QueryDosDeviceA" */
#define DECLARE_NAMEOF_API_QUERYDOSDEVICEA                                            \
    CHAR NAMEOF_API_QUERYDOSDEVICEA[] = {                                             \
        'Q', 'u', 'e', 'r', 'y', 'D', 'o', 's', 'D', 'e', 'v', 'i', 'c', 'e', 'A', 0, \
    };
/* "QueryDosDeviceW" */
#define DECLARE_NAMEOF_API_QUERYDOSDEVICEW                                            \
    CHAR NAMEOF_API_QUERYDOSDEVICEW[] = {                                             \
        'Q', 'u', 'e', 'r', 'y', 'D', 'o', 's', 'D', 'e', 'v', 'i', 'c', 'e', 'W', 0, \
    };

/* @brief
    Retrieves information about MS-DOS device names.
    The function can obtain the current mapping for a particular MS-DOS device name.
    The function can also obtain a list of all existing MS-DOS device names.
    MS-DOS device names are stored as junctions in the object namespace.
    The code that converts an MS-DOS path into a corresponding path uses these junctions to map MS-DOS devices and drive letters.
    The QueryDosDevice function enables an application to query the names of the junctions used to implement the MS-DOS device namespace as well as the value of
   each specific junction.
 */
typedef DWORD(WINAPI *QUERYDOSDEVICEA)(IN OUT LPCSTR lpDeviceName, OUT LPSTR lpTargetPath, IN DWORD ucchMax);

typedef DWORD(WINAPI *QUERYDOSDEVICEW)(IN OUT LPCWSTR lpDeviceName, OUT LPWSTR lpTargetPath, IN DWORD ucchMax);

/* "GetSystemFirmwareTable" */
#define DECLARE_NAMEOF_API_GETSYSTEMFIRMWARETABLE                                                                        \
    CHAR NAMEOF_API_GETSYSTEMFIRMWARETABLE[] = {                                                                         \
        'G', 'e', 't', 'S', 'y', 's', 't', 'e', 'm', 'F', 'i', 'r', 'm', 'w', 'a', 'r', 'e', 'T', 'a', 'b', 'l', 'e', 0, \
    };

/* @brief
    Retrieves the specified firmware table from the firmware table provider.
 */
typedef UINT(__stdcall *GETSYSTEMFIRMWARETABLE)(___in DWORD FirmwareTableProviderSignature, ___in DWORD FirmwareTableID, ___out PVOID pFirmwareTableBuffer,
                                                ___in DWORD BufferSize);

#if defined _MBCS || defined MBCS
#define DECLARE_NAMEOF_API_QUERYFULLPROCESSIMAGENAME DECLARE_NAMEOF_API_QUERYFULLPROCESSIMAGENAMEA

#define NAMEOF_API_QUERYFULLPROCESSIMAGENAME NAMEOF_API_QUERYFULLPROCESSIMAGENAMEA
#define QUERYFULLPROCESSIMAGENAME QUERYFULLPROCESSIMAGENAMEA
#elif defined _UNICODE || defined UNICODE
#define DECLARE_NAMEOF_API_QUERYFULLPROCESSIMAGENAME DECLARE_NAMEOF_API_QUERYFULLPROCESSIMAGENAMEW

#define NAMEOF_API_QUERYFULLPROCESSIMAGENAME NAMEOF_API_QUERYFULLPROCESSIMAGENAMEW
#define QUERYFULLPROCESSIMAGENAME QUERYFULLPROCESSIMAGENAMEW
#endif

/* "QueryFullProcessImageNameA" */
#define DECLARE_NAMEOF_API_QUERYFULLPROCESSIMAGENAMEA                                                                                        \
    CHAR NAMEOF_API_QUERYFULLPROCESSIMAGENAMEA[] = {                                                                                         \
        'Q', 'u', 'e', 'r', 'y', 'F', 'u', 'l', 'l', 'P', 'r', 'o', 'c', 'e', 's', 's', 'I', 'm', 'a', 'g', 'e', 'N', 'a', 'm', 'e', 'A', 0, \
    };
/* "QueryFullProcessImageNameW" */
#define DECLARE_NAMEOF_API_QUERYFULLPROCESSIMAGENAMEW                                                                                        \
    CHAR NAMEOF_API_QUERYFULLPROCESSIMAGENAMEW[] = {                                                                                         \
        'Q', 'u', 'e', 'r', 'y', 'F', 'u', 'l', 'l', 'P', 'r', 'o', 'c', 'e', 's', 's', 'I', 'm', 'a', 'g', 'e', 'N', 'a', 'm', 'e', 'W', 0, \
    };

/* @brief
    Retrieves the full name of the executable image for the specified process.
 */
typedef BOOL(__stdcall *QUERYFULLPROCESSIMAGENAMEA)(___in HANDLE hProcess, ___in DWORD dwFlags, ___out LPSTR lpExeName, __inout PDWORD lpdwSize);

typedef BOOL(__stdcall *QUERYFULLPROCESSIMAGENAMEW)(___in HANDLE hProcess, ___in DWORD dwFlags, ___out LPWSTR lpExeName, __inout PDWORD lpdwSize);

typedef VOID(__stdcall *RTLCAPTURECONTEXT)(OUT PCONTEXT ContextRecord);
/* "RtlCaptureContext" */
#define DECLARE_NAMEOF_API_RTLCAPTURECONTEXT                                                    \
    CHAR NAMEOF_API_RTLCAPTURECONTEXT[] = {                                                     \
        'R', 't', 'l', 'C', 'a', 'p', 't', 'u', 'r', 'e', 'C', 'o', 'n', 't', 'e', 'x', 't', 0, \
    };

// LOCALE
#if _MSC_FULL_VER >= 140050727

#else

#ifndef __MINGW32__

#define LOCALE_ILANGUAGE 0x00000001  // language id
#define LOCALE_SLANGUAGE 0x00000002  // localized name of language
#define LOCALE_SENGLANGUAGE 0x00001001  // English name of language
#define LOCALE_SABBREVLANGNAME 0x00000003  // abbreviated language name
#define LOCALE_SNATIVELANGNAME 0x00000004  // native name of language

#define LOCALE_ICOUNTRY 0x00000005  // country code
#define LOCALE_SCOUNTRY 0x00000006  // localized name of country
#define LOCALE_SENGCOUNTRY 0x00001002  // English name of country
#define LOCALE_SABBREVCTRYNAME 0x00000007  // abbreviated country name
#define LOCALE_SNATIVECTRYNAME 0x00000008  // native name of country
#define LOCALE_IGEOID 0x0000005B  // geographical location id

#define LOCALE_IDEFAULTLANGUAGE 0x00000009  // default language id
#define LOCALE_IDEFAULTCOUNTRY 0x0000000A  // default country code
#define LOCALE_IDEFAULTCODEPAGE 0x0000000B  // default oem code page
#define LOCALE_IDEFAULTANSICODEPAGE 0x00001004  // default ansi code page
#define LOCALE_IDEFAULTMACCODEPAGE 0x00001011  // default mac code page

#define LOCALE_SLIST 0x0000000C  // list item separator
#define LOCALE_IMEASURE 0x0000000D  // 0 = metric, 1 = US

#define LOCALE_SDECIMAL 0x0000000E  // decimal separator
#define LOCALE_STHOUSAND 0x0000000F  // thousand separator
#define LOCALE_SGROUPING 0x00000010  // digit grouping
#define LOCALE_IDIGITS 0x00000011  // number of fractional digits
#define LOCALE_ILZERO 0x00000012  // leading zeros for decimal
#define LOCALE_INEGNUMBER 0x00001010  // negative number mode
#define LOCALE_SNATIVEDIGITS 0x00000013  // native digits for 0-9

#define LOCALE_SCURRENCY 0x00000014  // local monetary symbol
#define LOCALE_SINTLSYMBOL 0x00000015  // intl monetary symbol
#define LOCALE_SMONDECIMALSEP 0x00000016  // monetary decimal separator
#define LOCALE_SMONTHOUSANDSEP 0x00000017  // monetary thousand separator
#define LOCALE_SMONGROUPING 0x00000018  // monetary grouping
#define LOCALE_ICURRDIGITS 0x00000019  // # local monetary digits
#define LOCALE_IINTLCURRDIGITS 0x0000001A  // # intl monetary digits
#define LOCALE_ICURRENCY 0x0000001B  // positive currency mode
#define LOCALE_INEGCURR 0x0000001C  // negative currency mode

#define LOCALE_SDATE 0x0000001D  // date separator (derived from LOCALE_SSHORTDATE, use that instead)
#define LOCALE_STIME 0x0000001E  // time separator (derived from LOCALE_STIMEFORMAT, use that instead)
#define LOCALE_SSHORTDATE 0x0000001F  // short date format string
#define LOCALE_SLONGDATE 0x00000020  // long date format string
#define LOCALE_STIMEFORMAT 0x00001003  // time format string
#define LOCALE_IDATE 0x00000021  // short date format ordering (derived from LOCALE_SSHORTDATE, use that instead)
#define LOCALE_ILDATE 0x00000022  // long date format ordering (derived from LOCALE_SLONGDATE, use that instead)
#define LOCALE_ITIME 0x00000023  // time format specifier (derived from LOCALE_STIMEFORMAT, use that instead)
#define LOCALE_ITIMEMARKPOSN 0x00001005  // time marker position (derived from LOCALE_STIMEFORMAT, use that instead)
#define LOCALE_ICENTURY 0x00000024  // century format specifier (short date, LOCALE_SSHORTDATE is preferred)
#define LOCALE_ITLZERO 0x00000025  // leading zeros in time field (derived from LOCALE_STIMEFORMAT, use that instead)
#define LOCALE_IDAYLZERO 0x00000026  // leading zeros in day field (short date, LOCALE_SSHORTDATE is preferred)
#define LOCALE_IMONLZERO 0x00000027  // leading zeros in month field (short date, LOCALE_SSHORTDATE is preferred)
#define LOCALE_S1159 0x00000028  // AM designator
#define LOCALE_S2359 0x00000029  // PM designator

#define LOCALE_ICALENDARTYPE 0x00001009  // type of calendar specifier
#define LOCALE_IOPTIONALCALENDAR 0x0000100B  // additional calendar types specifier
#define LOCALE_IFIRSTDAYOFWEEK 0x0000100C  // first day of week specifier
#define LOCALE_IFIRSTWEEKOFYEAR 0x0000100D  // first week of year specifier

#define LOCALE_SDAYNAME1 0x0000002A  // long name for Monday
#define LOCALE_SDAYNAME2 0x0000002B  // long name for Tuesday
#define LOCALE_SDAYNAME3 0x0000002C  // long name for Wednesday
#define LOCALE_SDAYNAME4 0x0000002D  // long name for Thursday
#define LOCALE_SDAYNAME5 0x0000002E  // long name for Friday
#define LOCALE_SDAYNAME6 0x0000002F  // long name for Saturday
#define LOCALE_SDAYNAME7 0x00000030  // long name for Sunday
#define LOCALE_SABBREVDAYNAME1 0x00000031  // abbreviated name for Monday
#define LOCALE_SABBREVDAYNAME2 0x00000032  // abbreviated name for Tuesday
#define LOCALE_SABBREVDAYNAME3 0x00000033  // abbreviated name for Wednesday
#define LOCALE_SABBREVDAYNAME4 0x00000034  // abbreviated name for Thursday
#define LOCALE_SABBREVDAYNAME5 0x00000035  // abbreviated name for Friday
#define LOCALE_SABBREVDAYNAME6 0x00000036  // abbreviated name for Saturday
#define LOCALE_SABBREVDAYNAME7 0x00000037  // abbreviated name for Sunday
#define LOCALE_SMONTHNAME1 0x00000038  // long name for January
#define LOCALE_SMONTHNAME2 0x00000039  // long name for February
#define LOCALE_SMONTHNAME3 0x0000003A  // long name for March
#define LOCALE_SMONTHNAME4 0x0000003B  // long name for April
#define LOCALE_SMONTHNAME5 0x0000003C  // long name for May
#define LOCALE_SMONTHNAME6 0x0000003D  // long name for June
#define LOCALE_SMONTHNAME7 0x0000003E  // long name for July
#define LOCALE_SMONTHNAME8 0x0000003F  // long name for August
#define LOCALE_SMONTHNAME9 0x00000040  // long name for September
#define LOCALE_SMONTHNAME10 0x00000041  // long name for October
#define LOCALE_SMONTHNAME11 0x00000042  // long name for November
#define LOCALE_SMONTHNAME12 0x00000043  // long name for December
#define LOCALE_SMONTHNAME13 0x0000100E  // long name for 13th month (if exists)
#define LOCALE_SABBREVMONTHNAME1 0x00000044  // abbreviated name for January
#define LOCALE_SABBREVMONTHNAME2 0x00000045  // abbreviated name for February
#define LOCALE_SABBREVMONTHNAME3 0x00000046  // abbreviated name for March
#define LOCALE_SABBREVMONTHNAME4 0x00000047  // abbreviated name for April
#define LOCALE_SABBREVMONTHNAME5 0x00000048  // abbreviated name for May
#define LOCALE_SABBREVMONTHNAME6 0x00000049  // abbreviated name for June
#define LOCALE_SABBREVMONTHNAME7 0x0000004A  // abbreviated name for July
#define LOCALE_SABBREVMONTHNAME8 0x0000004B  // abbreviated name for August
#define LOCALE_SABBREVMONTHNAME9 0x0000004C  // abbreviated name for September
#define LOCALE_SABBREVMONTHNAME10 0x0000004D  // abbreviated name for October
#define LOCALE_SABBREVMONTHNAME11 0x0000004E  // abbreviated name for November
#define LOCALE_SABBREVMONTHNAME12 0x0000004F  // abbreviated name for December
#define LOCALE_SABBREVMONTHNAME13 0x0000100F  // abbreviated name for 13th month (if exists)

#define LOCALE_SPOSITIVESIGN 0x00000050  // positive sign
#define LOCALE_SNEGATIVESIGN 0x00000051  // negative sign
#define LOCALE_IPOSSIGNPOSN 0x00000052  // positive sign position (derived from INEGCURR)
#define LOCALE_INEGSIGNPOSN 0x00000053  // negative sign position (derived from INEGCURR)
#define LOCALE_IPOSSYMPRECEDES 0x00000054  // mon sym precedes pos amt (derived from ICURRENCY)
#define LOCALE_IPOSSEPBYSPACE 0x00000055  // mon sym sep by space from pos amt (derived from ICURRENCY)
#define LOCALE_INEGSYMPRECEDES 0x00000056  // mon sym precedes neg amt (derived from INEGCURR)
#define LOCALE_INEGSEPBYSPACE 0x00000057  // mon sym sep by space from neg amt (derived from INEGCURR)

#define LOCALE_FONTSIGNATURE 0x00000058  // font signature
#define LOCALE_SISO639LANGNAME 0x00000059  // ISO abbreviated language name
#define LOCALE_SISO3166CTRYNAME 0x0000005A  // ISO abbreviated country name

#define LOCALE_IDEFAULTEBCDICCODEPAGE 0x00001012  // default ebcdic code page
#define LOCALE_IPAPERSIZE 0x0000100A  // 1 = letter, 5 = legal, 8 = a3, 9 = a4
#define LOCALE_SENGCURRNAME 0x00001007  // english name of currency
#define LOCALE_SNATIVECURRNAME 0x00001008  // native name of currency
#define LOCALE_SYEARMONTH 0x00001006  // year month format string
#define LOCALE_SSORTNAME 0x00001013  // sort name
#define LOCALE_IDIGITSUBSTITUTION 0x00001014  // 0 = context, 1 = none, 2 = national

#define LOCALE_SNAME 0x0000005c  // locale name (ie: en-us)
#define LOCALE_SDURATION 0x0000005d  // time duration format
#define LOCALE_SKEYBOARDSTOINSTALL 0x0000005e
#define LOCALE_SSHORTESTDAYNAME1 0x00000060  // Shortest day name for Monday
#define LOCALE_SSHORTESTDAYNAME2 0x00000061  // Shortest day name for Tuesday
#define LOCALE_SSHORTESTDAYNAME3 0x00000062  // Shortest day name for Wednesday
#define LOCALE_SSHORTESTDAYNAME4 0x00000063  // Shortest day name for Thursday
#define LOCALE_SSHORTESTDAYNAME5 0x00000064  // Shortest day name for Friday
#define LOCALE_SSHORTESTDAYNAME6 0x00000065  // Shortest day name for Saturday
#define LOCALE_SSHORTESTDAYNAME7 0x00000066  // Shortest day name for Sunday
#define LOCALE_SISO639LANGNAME2 0x00000067  // 3 character ISO abbreviated language name
#define LOCALE_SISO3166CTRYNAME2 0x00000068  // 3 character ISO country name
#define LOCALE_SNAN 0x00000069  // Not a Number
#define LOCALE_SPOSINFINITY 0x0000006a  // + Infinity
#define LOCALE_SNEGINFINITY 0x0000006b  // - Infinity
#define LOCALE_SSCRIPTS 0x0000006c  // Typical scripts in the locale
#define LOCALE_SPARENT 0x0000006d  // Fallback name for resources
#define LOCALE_SCONSOLEFALLBACKNAME 0x0000006e  // Fallback name for within the console
#define LOCALE_SLANGDISPLAYNAME 0x0000006f  // Lanugage Display Name for a language

#endif

#endif

typedef int(__stdcall *GETLOCALEINFOEX)(__in_opt LPCWSTR lpLocaleName, ___in LCTYPE LCType, __out_opt LPWSTR lpLCData, ___in int cchData);
/* "GetLocaleInfoEx" */
#define DECLARE_NAMEOF_API_GETLOCALEINFOEX                                            \
    CHAR NAMEOF_API_GETLOCALEINFOEX[] = {                                             \
        'G', 'e', 't', 'L', 'o', 'c', 'a', 'l', 'e', 'I', 'n', 'f', 'o', 'E', 'x', 0, \
    };

#endif
