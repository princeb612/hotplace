/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/io/system/windows/windows_registry.hpp>
// strsafe.h after tchar.h
// #include <strsafe.h>

namespace hotplace {
namespace io {

#if defined _MBCS || defined MBCS
return_t windows_registry::create_key(PHKEY phkey, HKEY hrootkey, LPCSTR sub_key, REGSAM regsam, DWORD option, LPSECURITY_ATTRIBUTES attrib)
#elif defined _UNICODE || defined UNICODE
return_t windows_registry::create_key(PHKEY phkey, HKEY hrootkey, LPCWSTR sub_key, REGSAM regsam, DWORD option, LPSECURITY_ATTRIBUTES attrib)
#endif
{
    return RegCreateKeyEx(hrootkey, sub_key, 0, nullptr, option, regsam, attrib, phkey, nullptr);
}

#if defined _MBCS || defined MBCS
return_t windows_registry::open_key(PHKEY phkey, HKEY hrootkey, LPCSTR sub_key, REGSAM regsam)
#elif defined _UNICODE || defined UNICODE
return_t windows_registry::open_key(PHKEY phkey, HKEY hrootkey, LPCWSTR sub_key, REGSAM regsam)
#endif
{
    return RegOpenKeyEx(hrootkey, sub_key, 0, regsam, phkey);
}

#if defined _MBCS || defined MBCS
return_t windows_registry::enumerate_subkeys(HKEY hkey, ENUM_CALLBACK_HANDLERA callback_handler, void* param)
#elif defined _UNICODE || defined UNICODE
return_t windows_registry::enumerate_subkeys(HKEY hkey, ENUM_CALLBACK_HANDLERW callback_handler, void* param)
#endif
{
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == callback_handler) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        DWORD index = 0;
        TCHAR buffer_key[(1 << 10)];
        DWORD buffer_key_cbsize = sizeof(buffer_key);
        LONG lret = RegEnumKeyEx(hkey, index, buffer_key, &buffer_key_cbsize, 0, 0, 0, 0);
        while (errorcode_t::success == lret) {
            callback_handler(buffer_key, param, nullptr);

            index++;
            buffer_key_cbsize = sizeof(buffer_key);
            lret = RegEnumKeyEx(hkey, index, buffer_key, &buffer_key_cbsize, 0, 0, 0, 0);
        }
    }
    __finally2 {}

    return ret;
}

#if defined _MBCS || defined MBCS
return_t windows_registry::enumerate_values(HKEY hkey, ENUM_CALLBACK_HANDLERA callback_handler, void* param)
#elif defined _UNICODE || defined UNICODE
return_t windows_registry::enumerate_values(HKEY hkey, ENUM_CALLBACK_HANDLERW callback_handler, void* param)
#endif
{
    return_t ret = errorcode_t::success;
    LONG lret = errorcode_t::success;

    __try2 {
        if (nullptr == callback_handler) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        DWORD index = 0;

        TCHAR buffer_value[(1 << 10)];
        BYTE buffer_data[(1 << 12)];
        DWORD dwType = 0;

        DWORD buffer_value_cbsize = sizeof(buffer_value);
        DWORD buffer_data_cbsize = sizeof(buffer_data);

        ENUM_VALUE_CONTEXT ctx;
        lret = RegEnumValue(hkey, index, buffer_value, &buffer_value_cbsize, 0, &dwType, buffer_data, &buffer_data_cbsize);
        while ((errorcode_t::success == lret) || (ERROR_MORE_DATA == lret)) {
            ctx.tszValue = buffer_value;
            ctx.dwValueSize = buffer_value_cbsize;
            ctx.dwType = dwType;
            ctx.pData = buffer_data;
            ctx.dwDataSize = buffer_data_cbsize;

            callback_handler(buffer_value, param, &ctx);

            index++;
            buffer_value_cbsize = sizeof(buffer_value);
            buffer_data_cbsize = sizeof(buffer_data);
            lret = RegEnumValue(hkey, index, buffer_value, &buffer_value_cbsize, 0, &dwType, buffer_data, &buffer_data_cbsize);
        }
    }
    __finally2 {}

    return ret;
}

#if defined _MBCS || defined MBCS
return_t windows_registry::delete_key(HKEY hrootkey, LPCSTR sub_key, DWORD option)
#elif defined _UNICODE || defined UNICODE
return_t windows_registry::delete_key(HKEY hrootkey, LPCWSTR sub_key, DWORD option)
#endif
{
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == sub_key) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        switch (option) {
            case registry_option_t::delete_sub_keys:
                ret = delete_sub_nodes(hrootkey, sub_key);
                break;

            default:
                ret = RegDeleteKey(hrootkey, sub_key);
                break;
        }
    }
    __finally2 {}

    return ret;
}

#if defined _MBCS || defined MBCS
return_t windows_registry::set_string(HKEY hkey, LPCSTR value, LPCSTR data)
#elif defined _UNICODE || defined UNICODE
return_t windows_registry::set_string(HKEY hkey, LPCWSTR value, LPCWSTR data)
#endif
{
    return_t ret = errorcode_t::success;

    __try2 {
        size_t sizeLen = _tcslen(data);
        ret = RegSetValueEx(hkey, value, 0, REG_SZ, (LPBYTE)data, (DWORD)sizeLen * sizeof(TCHAR));
    }
    __finally2 {}
    return ret;
}

#if defined _MBCS || defined MBCS
return_t windows_registry::set_value(HKEY hkey, LPCSTR value, DWORD type, void* data_ptr, DWORD cbsize)
#elif defined _UNICODE || defined UNICODE
return_t windows_registry::set_value(HKEY hkey, LPCWSTR value, DWORD type, void* data_ptr, DWORD cbsize)
#endif
{
    return_t ret = errorcode_t::success;

    __try2 { ret = RegSetValueEx(hkey, value, 0, type, (LPBYTE)data_ptr, cbsize); }
    __finally2 {}
    return ret;
}

#if defined _MBCS || defined MBCS
return_t windows_registry::delete_value(HKEY hkey, LPCSTR value)
#elif defined _UNICODE || defined UNICODE
return_t windows_registry::delete_value(HKEY hkey, LPCWSTR value)
#endif
{
    return_t ret = errorcode_t::success;

    __try2 { ret = RegDeleteValue(hkey, value); }
    __finally2 {}
    return ret;
}

#if defined _MBCS || defined MBCS
return_t windows_registry::query_value(HKEY hkey, LPCSTR value, LPDWORD type_ptr, void* data_ptr, LPDWORD data_cbsize_ptr)
#elif defined _UNICODE || defined UNICODE
return_t windows_registry::query_value(HKEY hkey, LPCWSTR value, LPDWORD type_ptr, void* data_ptr, LPDWORD data_cbsize_ptr)
#endif
{
    return_t ret = errorcode_t::success;

    __try2 { ret = RegQueryValueEx(hkey, value, nullptr, type_ptr, (LPBYTE)data_ptr, data_cbsize_ptr); }
    __finally2 {}
    return ret;
}

/* code from MSDN */
#if defined _MBCS || defined MBCS
return_t windows_registry::delete_sub_nodes(HKEY hrootkey, LPCSTR sub_key)
#elif defined _UNICODE || defined UNICODE
return_t windows_registry::delete_sub_nodes(HKEY hrootkey, LPCWSTR sub_key)
#endif
{
    return_t ret = errorcode_t::success;
    LPTSTR end_ptr = nullptr;
    DWORD size = 0;
    TCHAR buffer_name[MAX_PATH];
    HKEY hkey = nullptr;
    FILETIME filetime_written;
    TCHAR buffer_sub_key[MAX_PATH];
    return_t ret_del = errorcode_t::success;
    int retry = 0;

    __try2 {
        retry = 0;

        if (nullptr == sub_key) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        // SubKey 빈 문자열이고 keyRoot가 기본 루트키면 리턴한다.
        if (0 == _tcslen(sub_key)) {
            if ((HKEY_CLASSES_ROOT == hrootkey) || (HKEY_CURRENT_USER == hrootkey) || (HKEY_LOCAL_MACHINE == hrootkey) || (HKEY_USERS == hrootkey) ||
                (HKEY_CURRENT_CONFIG == hrootkey)) {
                ret = errorcode_t::invalid_parameter;
                __leave2;
            }
        }

        _tcsncpy(buffer_sub_key, sub_key, MAX_PATH);

        // First, see if we can delete the key without having
        // to recurse.

        ret = RegDeleteKey(hrootkey, buffer_sub_key);
        if (errorcode_t::success == ret) {
            __leave2;
        }

        ret = RegOpenKeyEx(hrootkey, buffer_sub_key, 0, KEY_READ, &hkey);
        if (errorcode_t::success != ret) {
            if (ERROR_FILE_NOT_FOUND == ret) {
                // Key not found
                ret = errorcode_t::success;
                __leave2;
            } else {
                // Error opening key
                __leave2;
            }
        }

        // Check for an ending slash and add one if it is missing.

        end_ptr = buffer_sub_key + _tcslen(buffer_sub_key);

        if (*(end_ptr - 1) != TEXT('\\')) {
            *end_ptr = TEXT('\\');
            end_ptr++;
            *end_ptr = TEXT('\0');
        }

        // Enumerate the keys

        size = MAX_PATH;
        ret = RegEnumKeyEx(hkey, 0, buffer_name, &size, nullptr, nullptr, nullptr, &filetime_written);
        if (errorcode_t::success == ret) {
            do {
                _tcsncpy(end_ptr, buffer_name, MAX_PATH);

                ret_del = delete_sub_nodes(hrootkey, buffer_sub_key);

                if (errorcode_t::success != ret_del) {
                    // StringCchPrintf(wszDebugLog, 4096, _T("ret_del : %d retry : %d"), ret_del, retry );
                    // OutputDebugString(wszDebugLog);
                    retry++;
                }

                if (DELTRYCOUNTMAX == retry) {
                    break;
                }

                size = MAX_PATH;

                ret = RegEnumKeyEx(hkey, 0, buffer_name, &size, nullptr, nullptr, nullptr, &filetime_written);

            } while (errorcode_t::success == ret);
        }

        end_ptr--;
        *end_ptr = TEXT('\0');

        RegCloseKey(hkey);

        // Try again to delete the key.

        ret = RegDeleteKey(hrootkey, buffer_sub_key);
        if (errorcode_t::success == ret) {
            __leave2;
        }
    }
    __finally2 {}

    return ret;
}

}  // namespace io
}  // namespace hotplace
