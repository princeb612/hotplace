/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/base/system/windows/sdk.hpp>
#include <sdk/base/system/windows/windows_version.hpp>

// COM
#include <comdef.h>
#include <comutil.h>

namespace hotplace {

return_t com_runtime_startup(uint32 init) {
    return_t ret = errorcode_t::success;

#if (_WIN32_WINNT >= 0x0400) || defined(_WIN32_DCOM)                                                        // DCOM
    ret = CoInitializeEx(0, COINIT_MULTITHREADED /*| COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE*/);  // HRESULT
#else
    ret = CoInitialize(0);
#endif
    ret = CoInitializeSecurity(nullptr,
                               -1,       // COM negotiates service
                               nullptr,  // Authentication services
                               nullptr,
                               RPC_C_AUTHN_LEVEL_DEFAULT,    // Default authentication
                               RPC_C_IMP_LEVEL_IMPERSONATE,  // Default Impersonation
                               nullptr,                      // Authentication info
                               EOAC_NONE,                    // Additional capabilities
                               nullptr);
    return ret;
}

return_t com_runtime_cleanup() {
    return_t ret = errorcode_t::success;

    CoUninitialize();
    return ret;
}

return_t is_windows64(BOOL* result) {
    return_t ret = errorcode_t::success;
    BOOL ret_result = FALSE;

    __try2 {
        if (nullptr == result) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        TCHAR buffer_wow64_dir[(1 << 8)];
        DWORD test = get_system_wow64_directory(buffer_wow64_dir, sizeof(buffer_wow64_dir) / sizeof(TCHAR));
        if (errorcode_t::success != test) {
            ret_result = FALSE;
        } else {
            ret_result = TRUE;
        }

        *result = ret_result;
    }
    __finally2 {
        // do nothing
    }

    return ret;
}

static return_t enum_modules_toolhelp(HANDLE process_handle, TYPE_CALLBACK_HANDLEREXV callback_handler, LPVOID param) {
    return_t ret = errorcode_t::success;
    HINSTANCE kernel32_handle = nullptr;
    HANDLE hToken = nullptr;
    HANDLE hModuleSnap = nullptr;
    DWORD dwOldAttrib = 0;

    CALLBACK_CONTROL cbControl = CONTINUE_CONTROL;

    __try2 {
        DECLARE_DLLNAME_KERNEL32;

        ret = get_module_handle(&kernel32_handle, DLLNAME_KERNEL32, loadlibrary_path_t::system_path, nullptr);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        CREATETOOLHELP32SNAPSHOT lpfnCreateToolhelp32Snapshot = nullptr;
        MODULE32FIRST lpfnModule32First = nullptr;
        MODULE32NEXT lpfnModule32Next = nullptr;

        DECLARE_NAMEOF_API_CREATETOOLHELP32SNAPSHOT;
        DECLARE_NAMEOF_API_MODULE32FIRST;
        DECLARE_NAMEOF_API_MODULE32NEXT;

        GETPROCADDRESS(CREATETOOLHELP32SNAPSHOT, lpfnCreateToolhelp32Snapshot, kernel32_handle, NAMEOF_API_CREATETOOLHELP32SNAPSHOT, ret, __leave2);
        GETPROCADDRESS(MODULE32FIRST, lpfnModule32First, kernel32_handle, NAMEOF_API_MODULE32FIRST, ret, __leave2);
        GETPROCADDRESS(MODULE32NEXT, lpfnModule32Next, kernel32_handle, NAMEOF_API_MODULE32NEXT, ret, __leave2);

        /* TOKEN_ADJUST_SESSIONID should be removed in the Windows NT 4.0 */
        ret =
            open_process_token(&hToken, process_handle,
                               TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_SESSIONID | TOKEN_ADJUST_DEFAULT | TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE);
        if (errorcode_t::success == ret) {
            ret = adjust_privileges(hToken, SE_DEBUG_NAME, SE_PRIVILEGE_ENABLED, &dwOldAttrib);
            if (errorcode_t::success != ret) {
                __leave2;
            }

            adjust_privileges(hToken, SE_ASSIGNPRIMARYTOKEN_NAME, SE_PRIVILEGE_ENABLED, nullptr);
            adjust_privileges(hToken, SE_INCREASE_QUOTA_NAME, SE_PRIVILEGE_ENABLED, nullptr);
        }

        hModuleSnap = lpfnCreateToolhelp32Snapshot(TH32CS_SNAPMODULE, 0);
        if (INVALID_HANDLE_VALUE == hModuleSnap) {
            ret = GetLastError();
            __leave2;
        }

        BOOL bRet = TRUE;
        MODULEENTRY32 me;
        memset(&me, 0, sizeof me);
        me.dwSize = sizeof me;
        bRet = lpfnModule32First(hModuleSnap, &me);
        if (FALSE == bRet) {
            ret = GetLastError();
            __leave2;
        }

        do {
            LPVOID pData[1];
            pData[0] = &me;
            callback_handler(enum_modules_t::enum_toolhelp, 1, pData, &cbControl, param);

            if (STOP_CONTROL == cbControl) {
                break;
            }

        } while (lpfnModule32Next(hModuleSnap, &me));
    }
    __finally2 {
        if (INVALID_HANDLE_VALUE != hModuleSnap) {
            CloseHandle(hModuleSnap);
        }
        if (nullptr != hToken) {
            adjust_privileges(hToken, SE_DEBUG_NAME, dwOldAttrib, nullptr);

            CloseHandle(hToken);
        }

        if (errorcode_t::success != ret) {
            // do nothing
        }
    }

    return ret;
}

static return_t enum_modules_psapi(HANDLE process_handle, TYPE_CALLBACK_HANDLEREXV callback_handler, LPVOID param) {
    return_t ret = errorcode_t::success;
    HINSTANCE psapi_handle = nullptr;

    CALLBACK_CONTROL cbControl = CONTINUE_CONTROL;

    __try2 {
        DECLARE_DLLNAME_PSAPI;

        /* psapi.dll not exist (Windows NT 4.0) */
        ret = get_module_handle(&psapi_handle, DLLNAME_PSAPI, loadlibrary_path_t::system_path, nullptr);
        if (errorcode_t::success != ret) {
            ret = get_module_handle(&psapi_handle, DLLNAME_PSAPI, loadlibrary_path_t::current_path, nullptr);
            if (errorcode_t::success != ret) {
                __leave2;
            }
        }

        BOOL bRet = TRUE;
        HMODULE aryModuleEnt[1024];
        DWORD cbNeeded = 0;

        ENUMPROCESSMODULES lpfnEnumProcessModules = nullptr;
        GETMODULEINFORMATION lpfnGetModuleInformation = nullptr;

        DECLARE_NAMEOF_API_ENUMPROCESSMODULES;
        DECLARE_NAMEOF_API_GETMODULEINFORMATION;

        GETPROCADDRESS(ENUMPROCESSMODULES, lpfnEnumProcessModules, psapi_handle, NAMEOF_API_ENUMPROCESSMODULES, ret, __leave2);
        GETPROCADDRESS(GETMODULEINFORMATION, lpfnGetModuleInformation, psapi_handle, NAMEOF_API_GETMODULEINFORMATION, ret, __leave2);

        bRet = lpfnEnumProcessModules(process_handle, aryModuleEnt, sizeof(aryModuleEnt), &cbNeeded);
        if (FALSE == bRet) {
            ret = GetLastError();
            __leave2;
        }

        DWORD dwCount = cbNeeded / sizeof(HMODULE);
        MODULEINFO mi;

        for (DWORD idx = 0; idx < dwCount; idx++) {
            bRet = lpfnGetModuleInformation(process_handle, aryModuleEnt[idx], &mi, sizeof mi);
            if (FALSE == bRet) {
                continue;
            }

            LPVOID pVector[2];
            pVector[0] = aryModuleEnt[idx];
            pVector[1] = &mi;
            callback_handler(enum_modules_t::enum_psapi, 2, pVector, &cbControl, param);
            if (STOP_CONTROL == cbControl) {
                break;
            }
        }
    }
    __finally2 {
        if (errorcode_t::success != ret) {
            // do nothing
        }
    }

    return ret;
}

return_t enum_modules(HANDLE process_handle, TYPE_CALLBACK_HANDLEREXV callback_handler, LPVOID param) {
    return_t ret = errorcode_t::success;
    BOOL is_winnt4 = FALSE;
    HMODULE psapi_handle = nullptr;

    __try2 {
        if (nullptr == process_handle || nullptr == callback_handler) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        const OSVERSIONINFOEXA* osvi = windows_version::get_instance()->get_osvi();
        if ((WINDOWSMAJORVERSION_NT4 == osvi->dwMajorVersion) && (WINDOWSMINORVERSION_NT4 == osvi->dwMinorVersion)) {
            is_winnt4 = TRUE;
        }

        if (FALSE == is_winnt4) {
            ret = enum_modules_toolhelp(process_handle, callback_handler, param);
        } else { /* Windows NT 4.0 */
            DECLARE_DLLNAME_PSAPI;

            /* not exist in Windows NT */
            ret = load_library(&psapi_handle, DLLNAME_PSAPI, loadlibrary_path_t::system_path, nullptr);
            if (errorcode_t::success != ret) {
                ret = load_library(&psapi_handle, DLLNAME_PSAPI, loadlibrary_path_t::current_path, nullptr);
                if (errorcode_t::success != ret) {
                    __leave2;
                }
            }
            ret = enum_modules_psapi(process_handle, callback_handler, param);
            if (nullptr != psapi_handle) {
                FreeLibrary(psapi_handle);
            }
        }
    }
    __finally2 {
        if (errorcode_t::success != ret) {
            // do nothing
        }
        if (psapi_handle) {
            FreeLibrary(psapi_handle);
        }
    }

    return ret;
}

return_t is_process_wow64(HANDLE hprocess, BOOL* result) {
    return_t ret = errorcode_t::success;
    ISWOW64PROCESS lpfnIsWow64Process = nullptr;
    BOOL ret_result = FALSE;

    __try2 {
        if (nullptr == result) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        DECLARE_DLLNAME_KERNEL32;

        HMODULE kernel32_handle = nullptr;
        ret = get_module_handle(&kernel32_handle, DLLNAME_KERNEL32, loadlibrary_path_t::system_path, nullptr);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        DECLARE_NAMEOF_API_ISWOW64PROCESS;
        GETPROCADDRESS(ISWOW64PROCESS, lpfnIsWow64Process, kernel32_handle, NAMEOF_API_ISWOW64PROCESS, ret, __leave2);

        BOOL test = lpfnIsWow64Process(hprocess, &ret_result);
        if (FALSE == test) {
            ret = ERROR_FUNCTION_FAILED;
            __leave2;
        }
    }
    __finally2 {
        if (nullptr != result) {
            *result = ret_result;
        }
        if (errorcode_t::success != ret) {
            // do nothing
        }
    }

    return ret;
}

return_t open_process_token(PHANDLE process_token, HANDLE process_handle, DWORD access) {
    return_t ret = errorcode_t::success;
    HMODULE advapi32_handle = nullptr;
    OPENPROCESSTOKEN lpfnOpenProcessToken = nullptr;

    __try2 {
        DECLARE_DLLNAME_ADVAPI32;

        ret = load_library(&advapi32_handle, DLLNAME_ADVAPI32, loadlibrary_path_t::system_path, nullptr);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        DECLARE_NAMEOF_API_OPENPROCESSTOKEN;

        GETPROCADDRESS(OPENPROCESSTOKEN, lpfnOpenProcessToken, advapi32_handle, NAMEOF_API_OPENPROCESSTOKEN, ret, __leave2);

        const OSVERSIONINFOEXA* osvi = windows_version::get_instance()->get_osvi();
        if (WINDOWSMAJORVERSION_NT4 == osvi->dwMajorVersion && WINDOWSMINORVERSION_NT4 == osvi->dwMinorVersion) {
            access &= ~TOKEN_ADJUST_SESSIONID;
        }

        BOOL bret = lpfnOpenProcessToken(process_handle, access, process_token);
        if (FALSE == bret) {
            ret = GetLastError();
            __leave2;
        }
    }
    __finally2 {
        if (nullptr != advapi32_handle) {
            FreeLibrary(advapi32_handle);
        }
    }

    return ret;
}

}  // namespace hotplace
