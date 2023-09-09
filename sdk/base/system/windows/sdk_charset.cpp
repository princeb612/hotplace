/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/base/system/windows/sdk.hpp>
#include <strsafe.h>
#include <string>

namespace hotplace {

#if defined _MBCS || defined MBCS
return_t adjust_privileges (HANDLE hToken, LPCSTR privilege, DWORD attrib, DWORD* old_attrib)
#elif defined _UNICODE || defined UNICODE
return_t adjust_privileges (HANDLE hToken, LPCWSTR privilege, DWORD attrib, DWORD* old_attrib)
#endif
{
    return_t ret = errorcode_t::success;
    TOKEN_PRIVILEGES Token, OldToken;
    LUID luid;
    HMODULE advapi32_handle = nullptr;

    LOOKUPPRIVILEGEVALUE lpfnLookupPrivilegeValue = nullptr;
    ADJUSTTOKENPRIVILEGES lpfnAdjustTokenPrivileges = nullptr;

    __try2
    {
        DECLARE_DLLNAME_ADVAPI32;

        ret = load_library (&advapi32_handle, DLLNAME_ADVAPI32, loadlibrary_path_t::system_path, nullptr);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        DECLARE_NAMEOF_API_LOOKUPPRIVILEGEVALUE;
        DECLARE_NAMEOF_API_ADJUSTTOKENPRIVILEGES;

        GETPROCADDRESS (LOOKUPPRIVILEGEVALUE,  lpfnLookupPrivilegeValue,  advapi32_handle, NAMEOF_API_LOOKUPPRIVILEGEVALUE,  ret, __leave2);
        GETPROCADDRESS (ADJUSTTOKENPRIVILEGES, lpfnAdjustTokenPrivileges, advapi32_handle, NAMEOF_API_ADJUSTTOKENPRIVILEGES, ret, __leave2);

        if ( !lpfnLookupPrivilegeValue (
                 nullptr,               // lookup privilege on local system
                 (LPCTSTR) privilege,   // privilege to lookup
                 &luid ) ) {            // receives LUID of privilege
            ret = ::GetLastError ();
            __leave2;
        }

        Token.PrivilegeCount = 1;
        Token.Privileges[0].Luid = luid;
        Token.Privileges[0].Attributes = attrib;

        // Enable the privilege or disable all privileges.
        DWORD dwTokenSize = sizeof (TOKEN_PRIVILEGES);
        if (FALSE == lpfnAdjustTokenPrivileges (hToken, FALSE, &Token, sizeof (TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES) &OldToken, &dwTokenSize) ) {
            ret = ::GetLastError ();
            __leave2;
        }

        if (ERROR_NOT_ALL_ASSIGNED == ::GetLastError ()) {
            __leave2;
        }

        if (nullptr != old_attrib) {
            *old_attrib = OldToken.Privileges[0].Attributes;
        }
    }
    __finally2
    {
        if (nullptr != advapi32_handle) {
            FreeLibrary (advapi32_handle);
        }

        if (errorcode_t::success != ret) {
            // do nothing
        }
    }

    return ret;
}

#if defined _MBCS || defined MBCS
return_t compose_windows_filepath (std::string& filepathname, const char* file_name, int32 path_type, const char* file_path)
#elif defined _UNICODE || defined UNICODE
return_t compose_windows_filepath (std::wstring& filepathname, const wchar_t* file_name, int32 path_type, const wchar_t* file_path)
#endif
{
    return_t ret = errorcode_t::success;

    __try2
    {
        filepathname.clear ();

        if (nullptr == file_name) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        switch (path_type) {
            case loadlibrary_path_t::system_path:
            {
                DECLARE_DLLNAME_KERNEL32;

                TCHAR buffer_system_path[MAX_PATH];
                memset (buffer_system_path, 0, sizeof (buffer_system_path));
                HMODULE handle_dll = GetModuleHandle (DLLNAME_KERNEL32);
                GetModuleFileName (handle_dll, buffer_system_path, MAX_PATH);

                filepathname = buffer_system_path;
                filepathname = dir_name (filepathname);
                filepathname += DIR_SEP_T;
                filepathname += file_name;
            }
            break;

            case loadlibrary_path_t::current_path:
            {
                TCHAR buffer_current_path[MAX_PATH];
                memset (buffer_current_path, 0, sizeof (buffer_current_path));
                ret = GetModuleFileName (nullptr, buffer_current_path, RTL_NUMBER_OF (buffer_current_path));

                filepathname = buffer_current_path;
                filepathname = dir_name (filepathname);
                filepathname += DIR_SEP_T;
                filepathname += file_name;
            }
            break;

            case loadlibrary_path_t::custom_path:
                if (nullptr == file_path) {
                    ret = errorcode_t::invalid_parameter;
                    __leave2;
                }

                filepathname = concat_filepath (file_path, file_name);
                break;
            default:
                break;
        }
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}


#if defined _MBCS || defined MBCS
return_t get_module_handle (HMODULE* module_handle, const char* dll_name, int32 path_type, const char* dll_path)
#elif defined _UNICODE || defined UNICODE
return_t get_module_handle (HMODULE* module_handle, const wchar_t* dll_name, int32 path_type, const wchar_t* dll_path)
#endif
{
    return_t ret = errorcode_t::success;

#if defined _MBCS || defined MBCS
    std::string filepathname;
#elif defined _UNICODE || defined UNICODE
    std::wstring filepathname;
#endif

    __try2
    {
        ret = compose_windows_filepath (filepathname, dll_name, path_type, dll_path);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        HMODULE handle_dll = GetModuleHandle (filepathname.c_str ());
        if (nullptr == handle_dll) {
            ret = GetLastError ();
            __leave2;
        }

        *module_handle = handle_dll;
    }
    __finally2
    {
        // do nothing
    }

    return ret;
}

#if defined _MBCS || defined MBCS
return_t get_system_wow64_directory (char* buffer, UINT size_buffer, UINT* size_copied)
#elif defined _UNICODE || defined UNICODE
return_t get_system_wow64_directory (wchar_t* buffer, UINT size_buffer, UINT* size_copied)
#endif
{
    /* This directory is not present on 32-bit Windows. */

    return_t ret = errorcode_t::success;
    HMODULE kernel32_handle = nullptr;
    GETSYSTEMWOW64DIRECTORY lpfnGetSystemWow64Directory = nullptr;

    __try2
    {
        DECLARE_DLLNAME_KERNEL32;

        ret = get_module_handle (&kernel32_handle, DLLNAME_KERNEL32, loadlibrary_path_t::system_path, nullptr);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        DECLARE_NAMEOF_API_GETSYSTEMWOW64DIRECTORY;

        GETPROCADDRESS (GETSYSTEMWOW64DIRECTORY, lpfnGetSystemWow64Directory, kernel32_handle, NAMEOF_API_GETSYSTEMWOW64DIRECTORY, ret, __leave2);

        INT nret = lpfnGetSystemWow64Directory (buffer, size_buffer /* in TCHARs */);
        if (0 == nret) {
            ret = GetLastError ();
            __leave2; /* __leave_trace(ret); */
        }
        /* optional parameter */
        if (nullptr != size_copied) {
            *size_copied = nret;
        }
    }
    __finally2
    {
        if (errorcode_t::success != ret) {
            // do nothing
        }
    }

    return ret;
}

#if defined _MBCS || defined MBCS
return_t load_library (HMODULE* module_handle, const char* dll_name, int32 path_type, const char* dll_path)
#elif defined _UNICODE || defined UNICODE
return_t load_library (HMODULE* module_handle, const wchar_t* dll_name, int32 path_type, const wchar_t* dll_path)
#endif
{
    return load_library_ex (module_handle, dll_name, 0, path_type, dll_path);
}

#if defined _MBCS || defined MBCS
return_t load_library_ex (HMODULE* module_handle, const char* dll_name, uint32 flags, int32 path_type, const char* dll_path)
#elif defined _UNICODE || defined UNICODE
return_t load_library_ex (HMODULE* module_handle, const wchar_t* dll_name, uint32 flags, int32 path_type, const wchar_t* dll_path)
#endif
{
    return_t ret = errorcode_t::success;

#if defined _MBCS || defined MBCS
    std::string filepathname;
#elif defined _UNICODE || defined UNICODE
    std::wstring filepathname;
#endif

    __try2
    {
        ret = compose_windows_filepath (filepathname, dll_name, path_type, dll_path);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        HMODULE handle_dll = LoadLibraryEx (filepathname.c_str (), nullptr, flags);
        if (nullptr == handle_dll) {
            ret = GetLastError ();
            __leave2;
        }

        *module_handle = handle_dll;
    }
    __finally2
    {
        // do nothing
    }

    return ret;
}


#if defined _MBCS || defined MBCS
return_t read_version (const char* version, WORD* vect, WORD level, INT* count)
#elif defined _UNICODE || defined UNICODE
return_t read_version (const wchar_t* version, WORD* vect, WORD level, INT* count)
#endif
{
    return_t ret = errorcode_t::success;
    INT nread = 0;

    __try2
    {
        if (nullptr == version || nullptr == vect || 0 == level) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        memset (vect, 0, sizeof (WORD) * level);

        INT data = 0;
        size_t movement = 0;
        size_t npos = 0;
        INT nret = 0;
        WORD i = 0;

        size_t version_cchsize = 0;
        StringCchLength (version, STRSAFE_MAX_CCH, &version_cchsize);

        while (i < level) {
#ifdef __STDC_WANT_SECURE_LIB__
            nret = _stscanf_s (version + npos, _T ("%d"), &data);
#else
            nret = _stscanf  (version + npos, _T ("%d"), &data);
#endif
            if (0 == nret) {
                ret = errorcode_t::internal_error;
                break;
            }
            nread++;

#if defined _MBCS || defined MBCS
            movement = strcspn (version + npos, _T ("."));
#elif defined _UNICODE || defined UNICODE
            movement = wcscspn (version + npos, _T ("."));
#endif

            vect[i] = (WORD) data;

            npos += (movement + 1);
            if (version_cchsize < npos) {
                break;
            }

            i++;
        }

        if (nullptr != count) {
            *count = nread;
        }
    }
    __finally2
    {
        if (errorcode_t::success != ret) {
            // do nothing
        }
    }

    return ret;
}

}  // namespace
