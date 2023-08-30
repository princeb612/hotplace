/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab textwidth=130 colorcolumn=+1: */
/**
 * @file dbghelp.h
 * @author Soo Han, Kim (hush@ahnlab.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_IO_SYSTEM_WINDOWS_SDK_DBGHELP__
#define __HOTPLACE_SDK_IO_SYSTEM_WINDOWS_SDK_DBGHELP__

/* MiniDumpWriteDump */
#define DECLARE_NAMEOF_API_MINIDUMPWRITEDUMP CHAR NAMEOF_API_MINIDUMPWRITEDUMP[] = { 'M', 'i', 'n', 'i', 'D', 'u', 'm', 'p', 'W', 'r', 'i', 't', 'e', 'D', 'u', 'm', 'p', 0, };
/* "SymCleanup" */
#define DECLARE_NAMEOF_API_SYMCLEANUP CHAR NAMEOF_API_SYMCLEANUP[] = { 'S', 'y', 'm', 'C', 'l', 'e', 'a', 'n', 'u', 'p', 0, };
/* "SymFunctionTableAccess" */
#define DECLARE_NAMEOF_API_SYMFUNCTIONTABLEACCESS CHAR NAMEOF_API_SYMFUNCTIONTABLEACCESS[] = { 'S', 'y', 'm', 'F', 'u', 'n', 'c', 't', 'i', 'o', 'n', 'T', 'a', 'b', 'l', 'e', 'A', 'c', 'c', 'e', 's', 's', 0, };
/* "SymFunctionTableAccess64" */
#define DECLARE_NAMEOF_API_SYMFUNCTIONTABLEACCESS64 CHAR NAMEOF_API_SYMFUNCTIONTABLEACCESS64[] = { 'S', 'y', 'm', 'F', 'u', 'n', 'c', 't', 'i', 'o', 'n', 'T', 'a', 'b', 'l', 'e', 'A', 'c', 'c', 'e', 's', 's', '6', '4', 0, };
/* "SymGetLineFromAddr" */
#define DECLARE_NAMEOF_API_SYMGETLINEFROMADDR CHAR NAMEOF_API_SYMGETLINEFROMADDR[] = { 'S', 'y', 'm', 'G', 'e', 't', 'L', 'i', 'n', 'e', 'F', 'r', 'o', 'm', 'A', 'd', 'd', 'r', 0, };
/* "SymGetLineFromAddr64" */
#define DECLARE_NAMEOF_API_SYMGETLINEFROMADDR64 CHAR NAMEOF_API_SYMGETLINEFROMADDR64[] = { 'S', 'y', 'm', 'G', 'e', 't', 'L', 'i', 'n', 'e', 'F', 'r', 'o', 'm', 'A', 'd', 'd', 'r', '6', '4', 0, };
/* "SymGetModuleBase" */
#define DECLARE_NAMEOF_API_SYMGETMODULEBASE CHAR NAMEOF_API_SYMGETMODULEBASE[] = { 'S', 'y', 'm', 'G', 'e', 't', 'M', 'o', 'd', 'u', 'l', 'e', 'B', 'a', 's', 'e', 0, };
/* "SymGetModuleBase64" */
#define DECLARE_NAMEOF_API_SYMGETMODULEBASE64 CHAR NAMEOF_API_SYMGETMODULEBASE64[] = { 'S', 'y', 'm', 'G', 'e', 't', 'M', 'o', 'd', 'u', 'l', 'e', 'B', 'a', 's', 'e', '6', '4', 0, };
/* "SymGetModuleInfo" */
#define DECLARE_NAMEOF_API_SYMGETMODULEINFO CHAR NAMEOF_API_SYMGETMODULEINFO[] = { 'S', 'y', 'm', 'G', 'e', 't', 'M', 'o', 'd', 'u', 'l', 'e', 'I', 'n', 'f', 'o', 0, };
/* "SymGetModuleInfo64" */
#define DECLARE_NAMEOF_API_SYMGETMODULEINFO64 CHAR NAMEOF_API_SYMGETMODULEINFO64[] = { 'S', 'y', 'm', 'G', 'e', 't', 'M', 'o', 'd', 'u', 'l', 'e', 'I', 'n', 'f', 'o', '6', '4', 0, };
/* "SymGetOptions" */
#define DECLARE_NAMEOF_API_SYMGETOPTIONS CHAR NAMEOF_API_SYMGETOPTIONS[] = { 'S', 'y', 'm', 'G', 'e', 't', 'O', 'p', 't', 'i', 'o', 'n', 's', 0, };
/* "SymGetSymFromAddr" */
#define DECLARE_NAMEOF_API_SYMGETSYMFROMADDR CHAR NAMEOF_API_SYMGETSYMFROMADDR[] = { 'S', 'y', 'm', 'G', 'e', 't', 'S', 'y', 'm', 'F', 'r', 'o', 'm', 'A', 'd', 'd', 'r', 0, };
/* "SymGetSymFromAddr64" */
#define DECLARE_NAMEOF_API_SYMGETSYMFROMADDR64 CHAR NAMEOF_API_SYMGETSYMFROMADDR64[] = { 'S', 'y', 'm', 'G', 'e', 't', 'S', 'y', 'm', 'F', 'r', 'o', 'm', 'A', 'd', 'd', 'r', '6', '4', 0, };
/* "SymInitialize" */
#define DECLARE_NAMEOF_API_SYMINITIALIZEA CHAR NAMEOF_API_SYMINITIALIZEA[] = { 'S', 'y', 'm', 'I', 'n', 'i', 't', 'i', 'a', 'l', 'i', 'z', 'e', 0, };
/* "SymInitializeW" */
#define DECLARE_NAMEOF_API_SYMINITIALIZEW CHAR NAMEOF_API_SYMINITIALIZEW[] = { 'S', 'y', 'm', 'I', 'n', 'i', 't', 'i', 'a', 'l', 'i', 'z', 'e', 'W', 0, };
/* "SymSetOptions" */
#define DECLARE_NAMEOF_API_SYMSETOPTIONS CHAR NAMEOF_API_SYMSETOPTIONS[] = { 'S', 'y', 'm', 'S', 'e', 't', 'O', 'p', 't', 'i', 'o', 'n', 's', 0, };
/* "StackWalk" */
#define DECLARE_NAMEOF_API_STACKWALK CHAR NAMEOF_API_STACKWALK[] = { 'S', 't', 'a', 'c', 'k', 'W', 'a', 'l', 'k', 0, };
/* "StackWalk64" */
#define DECLARE_NAMEOF_API_STACKWALK64 CHAR NAMEOF_API_STACKWALK64[] = { 'S', 't', 'a', 'c', 'k', 'W', 'a', 'l', 'k', '6', '4', 0, };
/* "UnDecorateSymbolName" */
#define DECLARE_NAMEOF_API_UNDECORATESYMBOLNAMEA CHAR NAMEOF_API_UNDECORATESYMBOLNAMEA[] = { 'U', 'n', 'D', 'e', 'c', 'o', 'r', 'a', 't', 'e', 'S', 'y', 'm', 'b', 'o', 'l', 'N', 'a', 'm', 'e', 0, };
/* "UnDecorateSymbolNameW" */
#define DECLARE_NAMEOF_API_UNDECORATESYMBOLNAMEW CHAR NAMEOF_API_UNDECORATESYMBOLNAMEW[] = { 'U', 'n', 'D', 'e', 'c', 'o', 'r', 'a', 't', 'e', 'S', 'y', 'm', 'b', 'o', 'l', 'N', 'a', 'm', 'e', 'W', 0, };
/* "SymLoadModule" 5.1 */
#define DECLARE_NAMEOF_API_SYMLOADMODULE CHAR NAMEOF_API_SYMLOADMODULE[] = { 'S', 'y', 'm', 'L', 'o', 'a', 'd', 'M', 'o', 'd', 'u', 'l', 'e', 0, };
/* "SymLoadModuleEx" 6.0 */
#define DECLARE_NAMEOF_API_SYMLOADMODULEEXA CHAR NAMEOF_API_SYMLOADMODULEEXA[] = { 'S', 'y', 'm', 'L', 'o', 'a', 'd', 'M', 'o', 'd', 'u', 'l', 'e', 'E', 'x', 0, };
#define DECLARE_NAMEOF_API_SYMLOADMODULEEXW CHAR NAMEOF_API_SYMLOADMODULEEXW[] = { 'S', 'y', 'm', 'L', 'o', 'a', 'd', 'M', 'o', 'd', 'u', 'l', 'e', 'E', 'x', 'W', 0, };
/* "SymLoadModule64" */
#define DECLARE_NAMEOF_API_SYMLOADMODULE64 CHAR NAMEOF_API_SYMLOADMODULE64[] = { 'S', 'y', 'm', 'L', 'o', 'a', 'd', 'M', 'o', 'd', 'u', 'l', 'e', '6', '4', 0, };

#if defined _MBCS || defined MBCS
#define DECLARE_NAMEOF_API_SYMINITIALIZE        DECLARE_NAMEOF_API_SYMINITIALIZEA
#define DECLARE_NAMEOF_API_UNDECORATESYMBOLNAME DECLARE_NAMEOF_API_UNDECORATESYMBOLNAMEA
#define DECLARE_NAMEOF_API_SYMLOADMODULEEX      DECLARE_NAMEOF_API_SYMLOADMODULEEXA

#define NAMEOF_API_SYMINITIALIZE                NAMEOF_API_SYMINITIALIZEA
#define NAMEOF_API_UNDECORATESYMBOLNAME         NAMEOF_API_UNDECORATESYMBOLNAMEA
#define NAMEOF_API_SYMLOADMODULEEX              NAMEOF_API_SYMLOADMODULEEXA
#elif defined _UNICODE || defined UNICODE
/* GetProcAddress(..., "SymInitializeW") 구현시 ERROR_PROC_NOT_FOUND(127) 발생 */
#define DECLARE_NAMEOF_API_SYMINITIALIZE        DECLARE_NAMEOF_API_SYMINITIALIZEA
#define DECLARE_NAMEOF_API_UNDECORATESYMBOLNAME DECLARE_NAMEOF_API_UNDECORATESYMBOLNAMEA
#define DECLARE_NAMEOF_API_SYMLOADMODULEEX      DECLARE_NAMEOF_API_SYMLOADMODULEEXA

#define NAMEOF_API_SYMINITIALIZE                NAMEOF_API_SYMINITIALIZEA
#define NAMEOF_API_UNDECORATESYMBOLNAME         NAMEOF_API_UNDECORATESYMBOLNAMEA
#define NAMEOF_API_SYMLOADMODULEEX              NAMEOF_API_SYMLOADMODULEEXA
#endif

#include <dbghelp.h>

/* @brief
    Writes user-mode minidump information to the specified file.
 */
typedef BOOL (__stdcall * MINIDUMPWRITEDUMP)
(
    HANDLE hProcess,
    DWORD ProcessId,
    HANDLE hFile,
    MINIDUMP_TYPE DumpType,
    PMINIDUMP_EXCEPTION_INFORMATION ExceptionParam,
    PMINIDUMP_USER_STREAM_INFORMATION UserStreamParam,
    PMINIDUMP_CALLBACK_INFORMATION CallbackParam
);

/* @brief
    Deallocates all resources associated with the process handle.
 */
typedef BOOL (__stdcall * SYMCLEANUP)
(
    HANDLE hProcess
);

/* @brief
    Retrieves the function table entry for the specified address.
 */
typedef PVOID (__stdcall * SYMFUNCTIONTABLEACCESS)
(
    HANDLE hProcess,
    DWORD AddrBase
);

typedef PVOID (__stdcall * SYMFUNCTIONTABLEACCESS64)
(
    HANDLE hProcess,
    DWORD64 AddrBase
);

/* @brief
    Locates the source line for the specified address.
 */
typedef BOOL (__stdcall * SYMGETLINEFROMADDR)
(
    HANDLE hProcess,
    DWORD dwAddr,
    PDWORD pdwDisplacement,
    PIMAGEHLP_LINE Line
);

typedef BOOL (__stdcall * SYMGETLINEFROMADDR64)
(
    HANDLE hProcess,
    DWORD64 dwAddr,
    PDWORD pdwDisplacement,
    PIMAGEHLP_LINE64 Line
);

/* @brief
    Retrieves the base address of the module that contains the specified address.
 */
typedef DWORD (__stdcall * SYMGETMODULEBASE)
(
    HANDLE hProcess,
    DWORD dwAddr
);
typedef DWORD64 (__stdcall * SYMGETMODULEBASE64)
(
    HANDLE hProcess,
    DWORD64 dwAddr
);

/* @brief
    Retrieves the module information of the specified module.
 */
typedef BOOL (__stdcall * SYMGETMODULEINFO)
(
    HANDLE hProcess,
    DWORD dwAddr,
    PIMAGEHLP_MODULE ModuleInfo
);

typedef BOOL (__stdcall * SYMGETMODULEINFO64)
(
    HANDLE hProcess,
    DWORD64 dwAddr,
    PIMAGEHLP_MODULE64 ModuleInfo
);

/* @brief
    Retrieves the current option mask.
 */
typedef DWORD (__stdcall * SYMGETOPTIONS)
(
    void
);

/* @brief
    Locates the symbol for the specified address.
    Note  This function is provided only for compatibility. Applications should use SymFromAddr.
 */
typedef BOOL (__stdcall * SYMGETSYMFROMADDR)
(
    HANDLE hProcess,
    DWORD Address,
    PDWORD Displacement,
    PIMAGEHLP_SYMBOL Symbol
);

typedef BOOL (__stdcall * SYMGETSYMFROMADDR64)
(
    HANDLE hProcess,
    DWORD64 Address,
    PDWORD64 Displacement,
    PIMAGEHLP_SYMBOL64 Symbol
);

/* @brief
    Initializes the symbol handler for a process.
 */
typedef BOOL (__stdcall * SYMINITIALIZE)
(
    HANDLE hProcess,
    PCTSTR UserSearchPath,
    BOOL fInvadeProcess
);

/* @brief
    Sets the options mask.
 */
typedef DWORD (__stdcall * SYMSETOPTIONS)
(
    DWORD SymOptions
);

/* @brief
    Obtains a stack trace.
 */
typedef BOOL (__stdcall *STACKWALK)
(
    DWORD MachineType,
    HANDLE hProcess,
    HANDLE hThread,
    LPSTACKFRAME StackFrame,
    PVOID ContextRecord,
    PREAD_PROCESS_MEMORY_ROUTINE ReadMemoryRoutine,
    PFUNCTION_TABLE_ACCESS_ROUTINE FunctionTableAccessRoutine,
    PGET_MODULE_BASE_ROUTINE GetModuleBaseRoutine,
    PTRANSLATE_ADDRESS_ROUTINE TranslateAddress
);

typedef BOOL (__stdcall * STACKWALK64)
(
    DWORD MachineType,
    HANDLE hProcess,
    HANDLE hThread,
    LPSTACKFRAME64 StackFrame,
    PVOID ContextRecord,
    PREAD_PROCESS_MEMORY_ROUTINE64 ReadMemoryRoutine,
    PFUNCTION_TABLE_ACCESS_ROUTINE64 FunctionTableAccessRoutine,
    PGET_MODULE_BASE_ROUTINE64 GetModuleBaseRoutine,
    PTRANSLATE_ADDRESS_ROUTINE64 TranslateAddress
);

/* @brief
    Undecorates the specified decorated C++ symbol name.
 */
typedef DWORD (__stdcall * UNDECORATESYMBOLNAME)
(
    PCTSTR DecoratedName,
    PTSTR UnDecoratedName,
    DWORD UndecoratedLength,
    DWORD Flags
);

/* @brief
    Loads the symbol table for the specified module.
 */
typedef DWORD (__stdcall * SYMLOADMODULE)
(
    HANDLE hProcess,
    HANDLE hFile,
    PCSTR ImageName,
    PCSTR ModuleName,
    DWORD BaseOfDll,
    DWORD SizeOfDll
);

typedef DWORD64 (__stdcall * SYMLOADMODULEEX)(
    HANDLE hProcess,
    HANDLE hFile,
    PCTSTR ImageName,
    PCTSTR ModuleName,
    DWORD64 BaseOfDll,
    DWORD DllSize,
    PMODLOAD_DATA Data,
    DWORD Flags
    );

/* @brief
    Loads the symbol table.
    This function has been superseded by the SymLoadModuleEx function.
 */
typedef DWORD64 (__stdcall * SYMLOADMODULE64)
(
    HANDLE hProcess,
    HANDLE hFile,
    PCSTR ImageName,
    PCSTR ModuleName,
    DWORD64 BaseOfDll,
    DWORD SizeOfDll
);

#endif
