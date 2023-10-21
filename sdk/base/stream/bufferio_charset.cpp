/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 * 2008.07.16   Soo Han, Kim        codename.merlin
 * 2023.08.15   Soo Han, Kim        fix : find_not_first_of, replace
 *                                  removed : replace1
 */

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include <hotplace/sdk/base/stream/bufferio.hpp>
#include <hotplace/sdk/base/stream/printf.hpp>

namespace hotplace {

#if defined _MBCS || defined MBCS
size_t bufferio::find_first_of(bufferio_context_t* handle, const char* find, size_t offset) { return find_first_of_routine(handle, 1, find, offset); }
#elif defined _UNICODE || defined UNICODE
size_t bufferio::wfind_first_of(bufferio_context_t* handle, const wchar_t* find, size_t offset) { return wfind_first_of_routine(handle, 1, find, offset); }
#endif

#if defined _MBCS || defined MBCS
size_t bufferio::find_first_of(bufferio_context_t* handle, int (*is_ctype_func)(int), size_t offset) {
    return find_first_of_routine(handle, 1, is_ctype_func, offset);
}
#elif defined _UNICODE || defined UNICODE
size_t bufferio::wfind_first_of(bufferio_context_t* handle, int (*is_ctype_func)(wint_t), size_t offset) {
    return wfind_first_of_routine(handle, 1, is_ctype_func, offset);
}
#endif

#if defined _MBCS || defined MBCS
size_t bufferio::find_not_first_of(bufferio_context_t* handle, const char* find, size_t offset) { return find_first_of_routine(handle, 0, find, offset); }
#elif defined _UNICODE || defined UNICODE
size_t bufferio::wfind_not_first_of(bufferio_context_t* handle, const wchar_t* find, size_t offset) { return wfind_first_of_routine(handle, 0, find, offset); }
#endif

#if defined _MBCS || defined MBCS
size_t bufferio::find_not_first_of(bufferio_context_t* handle, int (*is_ctype_func)(int), size_t offset) {
    return find_first_of_routine(handle, 0, is_ctype_func, offset);
}
#elif defined _UNICODE || defined UNICODE
size_t bufferio::wfind_not_first_of(bufferio_context_t* handle, int (*is_ctype_func)(wint_t), size_t offset) {
    return wfind_first_of_routine(handle, 0, is_ctype_func, offset);
}
#endif

#if defined _MBCS || defined MBCS
size_t bufferio::find_last_of(bufferio_context_t* handle, const char* find) { return find_last_of_routine(handle, 1, find); }
#elif defined _UNICODE || defined UNICODE
size_t bufferio::wfind_last_of(bufferio_context_t* handle, const wchar_t* find) { return wfind_last_of_routine(handle, 1, find); }
#endif

#if defined _MBCS || defined MBCS
size_t bufferio::find_last_of(bufferio_context_t* handle, int (*is_ctype_func)(int)) { return find_last_of_routine(handle, 1, is_ctype_func); }
#elif defined _UNICODE || defined UNICODE
size_t bufferio::wfind_last_of(bufferio_context_t* handle, int (*is_ctype_func)(wint_t)) { return wfind_last_of_routine(handle, 1, is_ctype_func); }
#endif

#if defined _MBCS || defined MBCS
size_t bufferio::find_not_last_of(bufferio_context_t* handle, const char* find) { return find_last_of_routine(handle, 0, find); }
#elif defined _UNICODE || defined UNICODE
size_t bufferio::wfind_not_last_of(bufferio_context_t* handle, const wchar_t* find) { return wfind_last_of_routine(handle, 0, find); }
#endif

#if defined _MBCS || defined MBCS
size_t bufferio::find_not_last_of(bufferio_context_t* handle, int (*is_ctype_func)(int)) { return find_last_of_routine(handle, 0, is_ctype_func); }
#elif defined _UNICODE || defined UNICODE
size_t bufferio::wfind_not_last_of(bufferio_context_t* handle, int (*is_ctype_func)(wint_t)) { return wfind_last_of_routine(handle, 0, is_ctype_func); }
#endif

#if defined _MBCS || defined MBCS
size_t bufferio::find_first_of_routine(bufferio_context_t* handle, int mode, const char* find, size_t offset)
#elif defined _UNICODE || defined UNICODE
size_t bufferio::wfind_first_of_routine(bufferio_context_t* handle, int mode, const wchar_t* find, size_t offset)
#endif
{
    return_t ret = errorcode_t::success;
    size_t ret_value = (size_t)-1;

    __try2 {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        if (BUFFERIO_CONTEXT_SIGNATURE != handle->signature) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }

        handle->bufferio_lock.enter();

        LPTSTR contents = nullptr;
        size_t contents_size = 0;
        size_t find_length = _tcslen(find);

        get(handle, (byte_t**)&contents, &contents_size);
        if (nullptr != contents) {
            if (offset < contents_size) {
                size_t pos = offset;
                LPTSTR cur = nullptr;
                while (pos < contents_size) {
                    cur = contents + pos;
                    if (0 == *cur) {
                        break;
                    }
                    int ret_compare = _tcsncmp(cur, find, find_length);
                    if ((1 == mode) && (0 == ret_compare)) {
                        ret_value = pos;
                        break;
                    } else if ((0 == mode) && (0 != ret_compare)) {
                        pos = find_length;
                        ret_value = find_length;
                        break;
                    }
                    pos++;
                }
            }
        }
        handle->bufferio_lock.leave();
    }
    __finally2 {
        // do nothing
    }
    return ret_value;
}

#if defined _MBCS || defined MBCS
size_t bufferio::find_first_of_routine(bufferio_context_t* handle, int mode, int (*is_ctype_func)(int), size_t offset)
#elif defined _UNICODE || defined UNICODE
size_t bufferio::wfind_first_of_routine(bufferio_context_t* handle, int mode, int (*is_ctype_func)(wint_t), size_t offset)
#endif
{
    return_t ret = errorcode_t::success;
    size_t ret_value = (size_t)-1;

    __try2 {
        if (nullptr == handle || nullptr == is_ctype_func) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        if (BUFFERIO_CONTEXT_SIGNATURE != handle->signature) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }

        handle->bufferio_lock.enter();

        LPTSTR contents = nullptr;
        size_t contents_size = 0;

        get(handle, (byte_t**)&contents, &contents_size);
        if (nullptr != contents) {
            if (offset < contents_size) {
                size_t pos = offset;
                LPTSTR cur = nullptr;
                while (pos < contents_size) {
                    cur = contents + pos;
                    if (0 == *cur) {
                        break;
                    }
                    int ret_compare = (*is_ctype_func)(*cur);
                    if ((1 == mode) && (0 != ret_compare)) {
                        ret_value = pos;
                        break;
                    } else if ((0 == mode) && (0 == ret_compare)) {
                        ret_value = pos;
                        break;
                    }
                    pos++;
                }
            }
        }
        handle->bufferio_lock.leave();
    }
    __finally2 {
        // do nothing
    }
    return ret_value;
}

#if defined _MBCS || defined MBCS
size_t bufferio::find_last_of_routine(bufferio_context_t* handle, int mode, const char* find)
#elif defined _UNICODE || defined UNICODE
size_t bufferio::wfind_last_of_routine(bufferio_context_t* handle, int mode, const wchar_t* find)
#endif
{
    return_t ret = errorcode_t::success;
    int ret_value = -1;

    __try2 {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        if (BUFFERIO_CONTEXT_SIGNATURE != handle->signature) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }

        handle->bufferio_lock.enter();

        LPTSTR contents = nullptr;
        size_t contents_size = 0;
        size_t find_length = _tcslen(find);

        get(handle, (byte_t**)&contents, &contents_size);
        if (nullptr != contents) {
            if (find_length <= contents_size) {
                size_t pos = contents_size - find_length;
                LPTSTR cur = nullptr;
                while (pos < contents_size) {
                    cur = contents + pos;
                    if (0 == pos) {
                        break;
                    }
                    int cmp = _tcsncmp(cur, find, find_length);
                    if ((1 == mode) && (0 == cmp)) {
                        ret_value = pos;
                        break;
                    } else if ((0 == mode) && (0 != cmp)) {
                        ret_value = pos;
                        break;
                    }
                    pos--;
                }
            }
        }
        handle->bufferio_lock.leave();
    }
    __finally2 {
        // do nothing
    }
    return ret_value;
}

#if defined _MBCS || defined MBCS
size_t bufferio::find_last_of_routine(bufferio_context_t* handle, int mode, int (*is_ctype_func)(int))
#elif defined _UNICODE || defined UNICODE
size_t bufferio::wfind_last_of_routine(bufferio_context_t* handle, int mode, int (*is_ctype_func)(wint_t))
#endif
{
    return_t ret = errorcode_t::success;
    int ret_value = -1;

    __try2 {
        if (nullptr == handle || nullptr == is_ctype_func) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        if (BUFFERIO_CONTEXT_SIGNATURE != handle->signature) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }

        handle->bufferio_lock.enter();

        LPTSTR contents = nullptr;
        size_t contents_size = 0;

        get(handle, (byte_t**)&contents, &contents_size);
        if (nullptr != contents) {
            if (0 == contents_size) {
                __leave2;
            }
#if defined _UNICODE || defined UNICODE
            if (contents_size % sizeof(wchar_t)) {
                __leave2;  // always even number, othercase odd number is an error
            }
#endif
            size_t pos = (contents_size / sizeof(TCHAR));
            LPTSTR cur = nullptr;
            while ((0 < pos) && (pos <= contents_size)) {
                cur = contents + pos - 1;
                if (0 == pos) {
                    break;
                }
                int ret_compare = (*is_ctype_func)(*cur);
                if ((1 == mode) && (0 != ret_compare)) {
                    ret_value = pos;
                    break;
                } else if ((0 == mode) && (0 == ret_compare)) {
                    ret_value = pos;
                    break;
                }
                pos--;
            }
        }
        handle->bufferio_lock.leave();
    }
    __finally2 {
        // do nothing
    }
    return ret_value;
}

#if defined _MBCS || defined MBCS
#define imp_find_first_of find_first_of
#elif defined _UNICODE || defined UNICODE
#define imp_find_first_of wfind_first_of
#endif

#if defined _MBCS || defined MBCS
return_t bufferio::replace(bufferio_context_t* handle, const char* from, const char* to, size_t begin, int flag)
#elif defined _UNICODE || defined UNICODE
return_t bufferio::wreplace(bufferio_context_t* handle, const wchar_t* from, const wchar_t* to, size_t begin, int flag)
#endif
{
    return_t ret = errorcode_t::success;
    size_t pos = 0;

    __try2 {
        if (nullptr == handle || nullptr == from || nullptr == to) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        if (BUFFERIO_CONTEXT_SIGNATURE != handle->signature) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }

        __try2 {
            handle->bufferio_lock.enter();

            size_t from_length = _tcslen(from);
            size_t to_length = _tcslen(to);

            if (from_length > handle->bufferio_size) {
                ret = errorcode_t::not_found;
                __leave2;
            }

            for (pos = begin; pos <= handle->bufferio_size - from_length; pos++) {
                size_t ret_find = imp_find_first_of(handle, from, pos);
                if (-1 != ret_find) {
                    cut(handle, ret_find * sizeof(TCHAR), from_length * sizeof(TCHAR));
                    insert(handle, ret_find * sizeof(TCHAR), to, to_length * sizeof(TCHAR));
                    if (bufferio_flag_t::run_once == flag) {
                        break;
                    }
                    pos += to_length;
                } else {
                    pos++;
                }
            }
        }
        __finally2 { handle->bufferio_lock.leave(); }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

#if defined _MBCS || defined MBCS
static int callback_printf(void* handle, const char* buf, int len)
#elif defined _UNICODE || defined UNICODE
static int callback_printfw(void* handle, const wchar_t* buf, int len)
#endif
{
    return_t ret = errorcode_t::success;

    __try2 {
        bufferio bio;
        ret = bio.write(reinterpret_cast<bufferio_context_t*>(handle), buf, sizeof(TCHAR) * len);
    }
    __finally2 {
        // do nothing
    }
    return (int)ret;
}

#if defined _MBCS || defined MBCS
return_t bufferio::printf(bufferio_context_t* handle, const char* fmt, ...)
#elif defined _UNICODE || defined UNICODE
return_t bufferio::printf(bufferio_context_t* handle, const wchar_t* fmt, ...)
#endif
{
    return_t ret = errorcode_t::success;
    va_list ap;

    va_start(ap, fmt);
    ret = vprintf(handle, fmt, ap);
    va_end(ap);
    return ret;
}

#if defined _MBCS || defined MBCS
return_t bufferio::vprintf(bufferio_context_t* handle, const char* fmt, va_list ap) {
    return_t ret = errorcode_t::success;
    int ret_vprintfworker = 0;

    ret_vprintfworker = vprintf_runtime(handle, callback_printf, fmt, ap);
    if (EOF == ret_vprintfworker) {
        ret = errorcode_t::internal_error;
    }

    return ret;
}
#elif defined _UNICODE || defined UNICODE
return_t bufferio::vprintf(bufferio_context_t* handle, const wchar_t* fmt, va_list ap) {
    return_t ret = errorcode_t::success;
    int ret_vprintfworker = 0;

    ret_vprintfworker = vprintf_runtimew(handle, callback_printfw, fmt, ap);
    if (EOF == ret_vprintfworker) {
        ret = errorcode_t::internal_error;
    }

    return ret;
}
#endif

}  // namespace hotplace
