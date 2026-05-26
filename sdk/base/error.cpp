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
    size_t size = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, code,
                                 MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&message_buffer, 0, NULL);

    std::string msg(message_buffer, size);
    LocalFree(message_buffer);
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

}  // namespace hotplace
