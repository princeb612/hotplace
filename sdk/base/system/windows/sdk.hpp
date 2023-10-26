/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_BASE_SYSTEM_WINDOWS_SDK__
#define __HOTPLACE_SDK_BASE_SYSTEM_WINDOWS_SDK__

#include <sdk/base/callback.hpp>
#include <sdk/base/charset.hpp>
#include <sdk/base/inline.hpp>
#include <sdk/base/syntax.hpp>

#if defined __MINGW32__

/*
 * @brief   do not define __in/__out (MINGW)
 * @desc
 *          // example
 *          #define __in
 *          #define __out
 *          #include <ostream>
 */
#define ___in
#define ___out

#define __bcount(size)
#define __ecount(size)

#define __in_bcount(size)
#define __in_bcount_nz(size)
#define __in_bcount_z(size)
#define __in_ecount(size)
#define __in_ecount_nz(size)
#define __in_ecount_z(size)

#define __out_bcount(size)
#define __out_bcount_nz(size)
#define __out_bcount_z(size)
#define __out_bcount_full(size)
#define __out_bcount_full_z(size)
#define __out_bcount_opt(size)
#define __out_bcount_part(size, length)
#define __out_bcount_part_z(size, length)
#define __out_bcount_part_opt(size, length)
#define __out_ecount(size)
#define __out_ecount_nz(size)
#define __out_ecount_opt(size)
#define __out_ecount_z(size)
#define __out_ecount_full(size)
#define __out_ecount_full_z(size)
#define __out_ecount_part(size, length)
#define __out_ecount_part_opt(size, length)
#define __out_ecount_part_z(size, length)

#define __inout
#define __inout_bcount(size)
#define __inout_bcount_nz(size)
#define __inout_bcount_z(size)
#define __inout_bcount_full(size)
#define __inout_bcount_part(size, length)
#define __inout_ecount(size)
#define __inout_ecount_nz(size)
#define __inout_ecount_z(size)
#define __inout_ecount_full(size)
#define __inout_ecount_part(size, length)

#define __deref_out
#define __deref_out_ecount(size)
#endif

/* TEXT("advapi32.dll") */
#define DECLARE_DLLNAME_ADVAPI32                                                                                       \
    TCHAR DLLNAME_ADVAPI32[] = {                                                                                       \
        _T('a'), _T('d'), _T('v'), _T('a'), _T('p'), _T('i'), _T('3'), _T('2'), _T('.'), _T('d'), _T('l'), _T('l'), 0, \
    };
/* TEXT("crypt32.dll") */
#define DECLARE_DLLNAME_CRYPT32                                                                               \
    TCHAR DLLNAME_CRYPT32[] = {                                                                               \
        _T('c'), _T('r'), _T('y'), _T('p'), _T('t'), _T('3'), _T('2'), _T('.'), _T('d'), _T('l'), _T('l'), 0, \
    };
/* TEXT("dbghelp.dll") */
#define DECLARE_DLLNAME_DBGHLP                                                                                \
    TCHAR DLLNAME_DBGHLP[] = {                                                                                \
        _T('d'), _T('b'), _T('g'), _T('h'), _T('e'), _T('l'), _T('p'), _T('.'), _T('d'), _T('l'), _T('l'), 0, \
    };
/* TEXT("imagehlp.dll") */
#define DECLARE_DLLNAME_IMAGEHLP                                                                                       \
    TCHAR DLLNAME_IMAGEHLP[] = {                                                                                       \
        _T('i'), _T('m'), _T('a'), _T('g'), _T('e'), _T('h'), _T('l'), _T('p'), _T('.'), _T('d'), _T('l'), _T('l'), 0, \
    };
/* TEXT("iphlpapi.dll") */
#define DECLARE_DLLNAME_IPHLPAPI                                                                                       \
    TCHAR DLLNAME_IPHLPAPI[] = {                                                                                       \
        _T('i'), _T('p'), _T('h'), _T('l'), _T('p'), _T('a'), _T('p'), _T('i'), _T('.'), _T('d'), _T('l'), _T('l'), 0, \
    };
/* TEXT("kernel32.dll") */
#define DECLARE_DLLNAME_KERNEL32                                                                                       \
    TCHAR DLLNAME_KERNEL32[] = {                                                                                       \
        _T('k'), _T('e'), _T('r'), _T('n'), _T('e'), _T('l'), _T('3'), _T('2'), _T('.'), _T('d'), _T('l'), _T('l'), 0, \
    };
/* TEXT("MpClient.dll") */
#define DECLARE_DLLNAME_MPCLIENT                                                                                       \
    TCHAR DLLNAME_MPCLIENT[] = {                                                                                       \
        _T('M'), _T('p'), _T('C'), _T('l'), _T('i'), _T('e'), _T('n'), _T('t'), _T('.'), _T('d'), _T('l'), _T('l'), 0, \
    };
/* TEXT("msi.dll") */
#define DECLARE_DLLNAME_MSI                                               \
    TCHAR DLLNAME_MSI[] = {                                               \
        _T('m'), _T('s'), _T('i'), _T('.'), _T('d'), _T('l'), _T('l'), 0, \
    };
/* TEXT("mswsock.dll") */
#define DECLARE_DLLNAME_MSWSOCK                                                                               \
    TCHAR DLLNAME_MSWSOCK[] = {                                                                               \
        _T('m'), _T('s'), _T('w'), _T('s'), _T('o'), _T('c'), _T('k'), _T('.'), _T('d'), _T('l'), _T('l'), 0, \
    };
/* TEXT("netapi32.dll") */
#define DECLARE_DLLNAME_NETAPI32                                                                                       \
    TCHAR DLLNAME_NETAPI32[] = {                                                                                       \
        _T('n'), _T('e'), _T('t'), _T('a'), _T('p'), _T('i'), _T('3'), _T('2'), _T('.'), _T('d'), _T('l'), _T('l'), 0, \
    };
/* TEXT("ntdll.dll") */
#define DECLARE_DLLNAME_NTDLL                                                               \
    TCHAR DLLNAME_NTDLL[] = {                                                               \
        _T('n'), _T('t'), _T('d'), _T('l'), _T('l'), _T('.'), _T('d'), _T('l'), _T('l'), 0, \
    };
/* TEXT("occache.dll") */
#define DECLARE_DLLNAME_OCCACHE                                                                               \
    TCHAR DLLNAME_OCCACHE[] = {                                                                               \
        _T('o'), _T('c'), _T('c'), _T('a'), _T('c'), _T('h'), _T('e'), _T('.'), _T('d'), _T('l'), _T('l'), 0, \
    };
/* TEXT("powrprof.dll") */
#define DECLARE_DLLNAME_POWERPROF                                                                                      \
    TCHAR DLLNAME_POWERPROF[] = {                                                                                      \
        _T('p'), _T('o'), _T('w'), _T('r'), _T('p'), _T('r'), _T('o'), _T('f'), _T('.'), _T('d'), _T('l'), _T('l'), 0, \
    };
/* TEXT("psapi.dll") */
#define DECLARE_DLLNAME_PSAPI                                                               \
    TCHAR DLLNAME_PSAPI[] = {                                                               \
        _T('p'), _T('s'), _T('a'), _T('p'), _T('i'), _T('.'), _T('d'), _T('l'), _T('l'), 0, \
    };
/* TEXT("secur32.dll") */
#define DECLARE_DLLNAME_SECUR32                                                                               \
    TCHAR DLLNAME_SECUR32[] = {                                                                               \
        _T('s'), _T('e'), _T('c'), _T('u'), _T('r'), _T('3'), _T('2'), _T('.'), _T('d'), _T('l'), _T('l'), 0, \
    };
/* TEXT("setupapi.dll") */
#define DECLARE_DLLNAME_SETUPAPI                                                                                       \
    TCHAR DLLNAME_SETUPAPI[] = {                                                                                       \
        _T('s'), _T('e'), _T('t'), _T('u'), _T('p'), _T('a'), _T('p'), _T('i'), _T('.'), _T('d'), _T('l'), _T('l'), 0, \
    };
/* TEXT("shell32.dll") */
#define DECLARE_DLLNAME_SHELL32                                                                               \
    TCHAR DLLNAME_SHELL32[] = {                                                                               \
        _T('s'), _T('h'), _T('e'), _T('l'), _T('l'), _T('3'), _T('2'), _T('.'), _T('d'), _T('l'), _T('l'), 0, \
    };
/* TEXT("shlwapi.dll") */
#define DECLARE_DLLNAME_SHLWAPI                                                                               \
    TCHAR DLLNAME_SHLWAPI[] = {                                                                               \
        _T('s'), _T('h'), _T('l'), _T('w'), _T('a'), _T('p'), _T('i'), _T('.'), _T('d'), _T('l'), _T('l'), 0, \
    };
/* TEXT("svrapi.dll") */
#define DECLARE_DLLNAME_SVRAPI                                                                       \
    TCHAR DLLNAME_SVRAPI[] = {                                                                       \
        _T('s'), _T('v'), _T('r'), _T('a'), _T('p'), _T('i'), _T('.'), _T('d'), _T('l'), _T('l'), 0, \
    };
/* TEXT("user32.dll") */
#define DECLARE_DLLNAME_USER32                                                                       \
    TCHAR DLLNAME_USER32[] = {                                                                       \
        _T('u'), _T('s'), _T('e'), _T('r'), _T('3'), _T('2'), _T('.'), _T('d'), _T('l'), _T('l'), 0, \
    };
/* TEXT("userenv.dll") */
#define DECLARE_DLLNAME_USERENV                                                                               \
    TCHAR DLLNAME_USERENV[] = {                                                                               \
        _T('u'), _T('s'), _T('e'), _T('r'), _T('e'), _T('n'), _T('v'), _T('.'), _T('d'), _T('l'), _T('l'), 0, \
    };
/* TEXT("wininet.dll") */
#define DECLARE_DLLNAME_WININET                                                                               \
    TCHAR DLLNAME_WININET[] = {                                                                               \
        _T('w'), _T('i'), _T('n'), _T('i'), _T('n'), _T('e'), _T('t'), _T('.'), _T('d'), _T('l'), _T('l'), 0, \
    };
/* TEXT("winio.dll") */
#define DECLARE_DLLNAME_WINIO                                                               \
    TCHAR DLLNAME_WINIO[] = {                                                               \
        _T('w'), _T('i'), _T('n'), _T('i'), _T('o'), _T('.'), _T('d'), _T('l'), _T('l'), 0, \
    };
/* TEXT("wintrust.dll") */
#define DECLARE_DLLNAME_WINTRUST                                                                                       \
    TCHAR DLLNAME_WINTRUST[] = {                                                                                       \
        _T('w'), _T('i'), _T('n'), _T('t'), _T('r'), _T('u'), _T('s'), _T('t'), _T('.'), _T('d'), _T('l'), _T('l'), 0, \
    };
/* TEXT("wldap32.dll") */
#define DECLARE_DLLNAME_WLDAP32                                                                               \
    TCHAR DLLNAME_WLDAP32[] = {                                                                               \
        _T('w'), _T('l'), _T('d'), _T('a'), _T('p'), _T('3'), _T('2'), _T('.'), _T('d'), _T('l'), _T('l'), 0, \
    };
/* TEXT("ws2_32.dll") */
#define DECLARE_DLLNAME_WS2_32                                                                       \
    TCHAR DLLNAME_WS2_32[] = {                                                                       \
        _T('w'), _T('s'), _T('2'), _T('_'), _T('3'), _T('2'), _T('.'), _T('d'), _T('l'), _T('l'), 0, \
    };
/* TEXT("wtsapi32.dll") */
#define DECLARE_DLLNAME_WTSAPI32                                                                                       \
    TCHAR DLLNAME_WTSAPI32[] = {                                                                                       \
        _T('w'), _T('t'), _T('s'), _T('a'), _T('p'), _T('i'), _T('3'), _T('2'), _T('.'), _T('d'), _T('l'), _T('l'), 0, \
    };
/* TEXT("wscapi.dll") */
#define DECLARE_DLLNAME_WSCAPI                                                                       \
    TCHAR DLLNAME_WSCAPI[] = {                                                                       \
        _T('w'), _T('s'), _T('c'), _T('a'), _T('p'), _T('i'), _T('.'), _T('d'), _T('l'), _T('l'), 0, \
    };

// advapi32.dll
#include <sdk/base/system/windows/sdk/advapi32.hpp>

// crypt32.dll
#include <sdk/base/system/windows/sdk/crypt32.hpp>

// dbghelp.dll
#include <sdk/base/system/windows/sdk/dbghelp.hpp>

// iphlpapi.dll
#include <sdk/base/system/windows/sdk/iphlpapi.hpp>

// kernel32.dll
#include <sdk/base/system/windows/sdk/kernel32.hpp>

// mpclient.dll
#include <sdk/base/system/windows/sdk/mpclient.hpp>

// msi.dll
#include <sdk/base/system/windows/sdk/msi.hpp>

// mswsock.dll
#include <sdk/base/system/windows/sdk/mswsock.hpp>

// netapi32.dll
#include <sdk/base/system/windows/sdk/netapi32.hpp>

// ntdll.dll
#include <sdk/base/system/windows/sdk/ntdll.hpp>

// occache.dll
#include <sdk/base/system/windows/sdk/occache.hpp>

// powerprof.dll
#include <sdk/base/system/windows/sdk/powerprof.hpp>

// psapi.dll
#include <sdk/base/system/windows/sdk/psapi.hpp>

// setupapi.dll
#include <sdk/base/system/windows/sdk/setupapi.hpp>

// shell32.dll
#include <sdk/base/system/windows/sdk/shell32.hpp>

// shlwapi.dll
#include <sdk/base/system/windows/sdk/shlwapi.hpp>

// svrapi.dll
#include <sdk/base/system/windows/sdk/svrapi.hpp>

// user32.dll
#include <sdk/base/system/windows/sdk/user32.hpp>

// userenv.dll
#include <sdk/base/system/windows/sdk/userenv.hpp>

// wininet.dll
#include <sdk/base/system/windows/sdk/wininet.hpp>

// winio.dll
#include <sdk/base/system/windows/sdk/winio.hpp>

// wintrust.dll
#include <sdk/base/system/windows/sdk/wintrust.hpp>

// wldap32.dll
#include <sdk/base/system/windows/sdk/wldap32.hpp>

// ws2_32.dll
#include <sdk/base/system/windows/sdk/ws2_32.hpp>

// wtsapi32.dll
#include <sdk/base/system/windows/sdk/wtsapi32.hpp>

// wscapi.dll
#include <sdk/base/system/windows/sdk/wscapi.hpp>

#define GETPROCADDRESS(function_type, function_pointer, module_handle, api_name, err_code, leave) \
    {                                                                                             \
        function_pointer = (function_type)::GetProcAddress(module_handle, api_name);              \
        if (nullptr == function_pointer) {                                                        \
            err_code = GetLastError();                                                            \
            leave;                                                                                \
        }                                                                                         \
    }
#define GETPROCADDRESSONLY(function_type, function_pointer, module_handle, api_name) function_pointer = (function_type)::GetProcAddress(module_handle, api_name)

namespace hotplace {

/**
 *  SE_CREATE_TOKEN_NAME                    TEXT("SeCreateTokenPrivilege")
 *  SE_ASSIGNPRIMARYTOKEN_NAME              TEXT("SeAssignPrimaryTokenPrivilege")
 *  SE_LOCK_MEMORY_NAME                     TEXT("SeLockMemoryPrivilege")
 *  SE_INCREASE_QUOTA_NAME                  TEXT("SeIncreaseQuotaPrivilege")
 *  SE_UNSOLICITED_INPUT_NAME               TEXT("SeUnsolicitedInputPrivilege")
 *  SE_MACHINE_ACCOUNT_NAME                 TEXT("SeMachineAccountPrivilege")
 *  SE_TCB_NAME                             TEXT("SeTcbPrivilege")
 *  SE_SECURITY_NAME                        TEXT("SeSecurityPrivilege")
 *  SE_TAKE_OWNERSHIP_NAME                  TEXT("SeTakeOwnershipPrivilege")
 *  SE_LOAD_DRIVER_NAME                     TEXT("SeLoadDriverPrivilege")
 *  SE_SYSTEM_PROFILE_NAME                  TEXT("SeSystemProfilePrivilege")
 *  SE_SYSTEMTIME_NAME                      TEXT("SeSystemtimePrivilege")
 *  SE_PROF_SINGLE_PROCESS_NAME             TEXT("SeProfileSingleProcessPrivilege")
 *  SE_INC_BASE_PRIORITY_NAME               TEXT("SeIncreaseBasePriorityPrivilege")
 *  SE_CREATE_PAGEFILE_NAME                 TEXT("SeCreatePagefilePrivilege")
 *  SE_CREATE_PERMANENT_NAME                TEXT("SeCreatePermanentPrivilege")
 *  SE_BACKUP_NAME                          TEXT("SeBackupPrivilege")
 *  SE_RESTORE_NAME                         TEXT("SeRestorePrivilege")
 *  SE_SHUTDOWN_NAME                        TEXT("SeShutdownPrivilege")
 *  SE_DEBUG_NAME                           TEXT("SeDebugPrivilege")
 *  SE_AUDIT_NAME                           TEXT("SeAuditPrivilege")
 *  SE_SYSTEM_ENVIRONMENT_NAME              TEXT("SeSystemEnvironmentPrivilege")
 *  SE_CHANGE_NOTIFY_NAME                   TEXT("SeChangeNotifyPrivilege")
 *  SE_REMOTE_SHUTDOWN_NAME                 TEXT("SeRemoteShutdownPrivilege")
 *  SE_UNDOCK_NAME                          TEXT("SeUndockPrivilege")
 *  SE_SYNC_AGENT_NAME                      TEXT("SeSyncAgentPrivilege")
 *  SE_ENABLE_DELEGATION_NAME               TEXT("SeEnableDelegationPrivilege")
 *  SE_MANAGE_VOLUME_NAME                   TEXT("SeManageVolumePrivilege")
 *  SE_IMPERSONATE_NAME                     TEXT("SeImpersonatePrivilege")
 *  SE_CREATE_GLOBAL_NAME                   TEXT("SeCreateGlobalPrivilege")
 */
return_t adjust_privileges(HANDLE token_handle, LPCSTR privilege, DWORD attrib, DWORD* old_attrib);
return_t adjust_privileges(HANDLE token_handle, LPCWSTR privilege, DWORD attrib, DWORD* old_attrib);

/**
 * @param   uint32 init [inopt]
 *          typedef enum tagCOINIT {
 *              COINIT_APARTMENTTHREADED = 0x2,
 *              COINIT_MULTITHREADED,
 *              COINIT_DISABLE_OLE1DDE = 0x4,
 *              COINIT_SPEED_OVER_MEMORY = 0x8
 *          } COINIT;
 */
return_t com_runtime_startup(uint32 init = COINIT_MULTITHREADED);
return_t com_runtime_cleanup();

enum enum_modules_t {
    enum_psapi = 1,
    enum_toolhelp,
};
/**
 * @brief   enumerate modules
 * @param   HANDLE process_handle [in]
 * @param   TYPE_CALLBACK_HANDLEREXV callback_handler [in]
 * @param   LPVOID param [in]
 * @example
 * return_t enum_modules_handler (uint32 type, uint32 count, void* data[], CALLBACK_CONTROL* control, void* parameter)
 * {
 *     switch(type)
 *     {
 *     case enum_modules_t::enum_toolhelp:
 *         {
 *             MODULEENTRY32* pEntry = (MODULEENTRY32*)data[0];
 *             DEBUG_PRINT(_T("module [%s]\n"), pEntry->szExePath);
 *         }
 *         break;
 *     case enum_modules_t::enum_psapi:
 *         {
 *             MODULEINFO* pEntry = (MODULEINFO*)data[1];
 *         }
 *         break;
 *     }
 *     return errorcode_t::success;
 * }
 */
return_t enum_modules(HANDLE process_handle, TYPE_CALLBACK_HANDLEREXV callback_handler, LPVOID param);

enum loadlibrary_path_t {
    system_path = 1,
    current_path,
    custom_path,
};

return_t get_module_handle(HMODULE* module_handle, const char* dll_name, int32 path_type = loadlibrary_path_t::system_path, const char* dll_path = nullptr);
return_t get_module_handle(HMODULE* module_handle, const wchar_t* dll_name, int32 path_type = loadlibrary_path_t::system_path,
                           const wchar_t* dll_path = nullptr);

return_t get_module_path(HMODULE module_handle, std::string& modulepath);
return_t get_module_path(HMODULE module_handle, std::wstring& modulepath);

return_t get_system_wow64_directory(char* buffer, UINT size, UINT* nCopied = nullptr);
return_t get_system_wow64_directory(wchar_t* buffer, UINT size, UINT* nCopied = nullptr);

return_t is_windows64(BOOL* ret);
return_t is_process_wow64(HANDLE process_handle, BOOL* pResult);

return_t load_library(HMODULE* module_handle, const char* dll_name, int32 path_type = loadlibrary_path_t::system_path, const char* dll_path = nullptr);
return_t load_library(HMODULE* module_handle, const wchar_t* dll_name, int32 path_type = loadlibrary_path_t::system_path, const wchar_t* dll_path = nullptr);

return_t load_library_ex(HMODULE* module_handle, const char* dll_name, uint32 flags, int32 path_type = loadlibrary_path_t::system_path,
                         const char* dll_path = nullptr);
return_t load_library_ex(HMODULE* module_handle, const wchar_t* dll_name, uint32 flags, int32 path_type = loadlibrary_path_t::system_path,
                         const wchar_t* dll_path = nullptr);

return_t open_process_token(PHANDLE process_token, HANDLE process_handle, DWORD access);

return_t read_version(const char* version_string, WORD* ver, WORD level, INT* count = nullptr);
return_t read_version(const wchar_t* version_string, WORD* ver, WORD level, INT* count = nullptr);

}  // namespace hotplace

#endif
