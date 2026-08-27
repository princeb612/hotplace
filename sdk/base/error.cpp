/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   error.cpp
 * @author Soo Han Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 * 2026.05.26   Soo Han and Gemini  refactoring
 */

#include <hotplace/sdk/base/error.hpp>
#include <hotplace/sdk/base/system/error.hpp>

namespace hotplace {

std::string return_t::error_code() const {
    std::string res;
    error_advisor::get_instance()->error_code(*this, res);
    return res;
}

std::string return_t::error_message() const {
    if (code >= ERROR_CODE_BEGIN) {
        std::string res;
        error_advisor::get_instance()->error_message(*this, res);
        return res;
    }
#if defined _WIN32 || defined WIN32
    char* message_buffer = nullptr;
    DWORD win32_code = code;
    if (HRESULT_FACILITY(code) == FACILITY_WIN32) {
        win32_code = HRESULT_CODE(code);
    }
    size_t size = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, win32_code,
                                 MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&message_buffer, 0, NULL);

    // CRT Debug Error Dialog / Crash - Gemini
    //  std::string(nullptr, 0) // even if 0 == size
    //    _ASSERTE(s != nullptr) -> MSVC (Windows CRT Debug) - /MDd /MTd
    std::string msg;
    if (0 == size || nullptr == message_buffer) {
        msg = "unknown";  // do nothing
    } else {
        msg.assign(message_buffer, size);

        LocalFree(message_buffer);

        // case message_buffer ends with \r\n
        while ((false == msg.empty()) && (msg.back() == '\r' || msg.back() == '\n')) {
            msg.pop_back();
        }
    }
    return msg;
#else
    char buf[256];
#if (_POSIX_C_SOURCE >= 200112L || _XOPEN_SOURCE >= 600) && !_GNU_SOURCE
    if (strerror_r(code, buf, sizeof(buf)) == 0) return std::string(buf);
#else
    return std::string(strerror_r(code, buf, sizeof(buf)));
#endif
#endif
    return "unknown error";
}

error_category_t return_t::category() const { return error_advisor::get_instance()->categoryof(*this); }

return_t get_lasterror(int code, int flags) {
    return_t ret = errorcode_t::success;
#if defined __linux__
    // errno.h 1~133
    // netdb.h -1~-105
    if (code < 0) {
        if (EAI_SYSTEM == code) {
            ret = (errno > 0 && errno <= 4095) ? static_cast<uint32>(errno) : static_cast<uint32>(errorcode_t::internal_error);
        } else {
            // kernel negative errno (-EINVAL, -ENOENT, ...)
            // if not kernel mode... negative errno is EAI_*
            uint32 abs_code = static_cast<uint32>(-code);
            ret = (abs_code >= 1 && abs_code <= 105) ? static_cast<uint32>(errorcode_t::error_eai_base) + abs_code : static_cast<uint32>(errorcode_t::out_of_range);
        }
    } else if (code > 0) {
        // POSIX errno
        ret = code;
    } else {
        ret = errorcode_t::success;
    }
#elif defined _WIN32 || defined _WIN64
    if (0 == flags) {
        ret = GetLastError();
    } else if (errorflag_t::wsaerror & flags) {
        ret = WSAGetLastError();
    }
#endif
    return ret;
}

}  // namespace hotplace
