/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   types.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_BASE_TYPES__
#define __HOTPLACE_SDK_BASE_TYPES__

#if defined __linux__
#include <hotplace/sdk/base/system/linux/types.hpp>
#elif defined _WIN32 || defined _WIN64
#include <hotplace/sdk/base/system/windows/types.hpp>
#endif

#if defined __linux__

#include <fcntl.h>
#include <sys/file.h>
#include <sys/types.h>
#include <unistd.h>

#if __GLIBC_MINOR__ >= 3
#include <sys/epoll.h>
#endif
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>

#elif defined _WIN32 || defined _WIN64

#include <hotplace/sdk/base/system/windows/types.hpp>

#endif

#include <string.h>

#include <map>
#include <string>
#include <vector>

namespace hotplace {

/**
 * byte type conflict
 *
 * #if __cplusplus >= 201703L
 * enum class byte : unsigned char;
 * ...
 * #endif
 */
typedef unsigned char byte_t;
typedef unsigned int uint;
// MSVC ADL (argument dependent lookup) problem
// typedef std::vector<byte_t> binary_t;
struct binary_t : public std::vector<byte_t> {
    using std::vector<byte_t>::vector;     // inherit ctor
    using std::vector<byte_t>::operator=;  // copy/move
};

enum loglevel_t : uint8 {
    loglevel_trace = 0,    // everything
    loglevel_debug = 2,    // debug
    loglevel_info = 4,     // information
    loglevel_warn = 6,     // warning
    loglevel_error = 8,    // error
    loglevel_fatal = 10,   // fatal error
    loglevel_notice = 12,  // notice
};

enum encoding_t {
    encoding_base16 = 1,     // BASE16
    encoding_base64 = 2,     // BASE64    + /
    encoding_base64url = 3,  // BASE64URL - _ without padding
};

#ifndef _WIN32  // winnt.h
#define RTL_NUMBER_OF(x) (sizeof(x) / sizeof(x[0]))
#define RTL_FIELD_TYPE(type, field) (((type *)0)->field)
#define RTL_FIELD_SIZE(type, field) (sizeof(((type *)0)->field))
#define FIELD_OFFSET(type, field) ((int32)(arch_t) & (((type *)0)->field))
#define RTL_SIZEOF_THROUGH_FIELD(type, field) (FIELD_OFFSET(type, field) + RTL_FIELD_SIZE(type, field))
#define RTL_NUMBER_OF_FIELD(type, field) (RTL_NUMBER_OF(RTL_FIELD_TYPE(type, field)))
#define RTL_PADDING_BETWEEN_FIELDS(type, field1, field2)                                                                                                  \
    ((FIELD_OFFSET(type, field2) > FIELD_OFFSET(type, field1)) ? (FIELD_OFFSET(type, field2) - FIELD_OFFSET(type, field1) - RTL_FIELD_SIZE(type, field1)) \
                                                               : (FIELD_OFFSET(type, field1) - FIELD_OFFSET(type, field2) - RTL_FIELD_SIZE(type, field2)))
#endif

#define adjust_range(var, minimum, maximum)    \
    {                                          \
        var = (var > minimum) ? var : minimum; \
        var = (var < maximum) ? var : maximum; \
    }

#if __GNUC__ >= 5
#define CONSTEXPR constexpr
#else
// error: redeclaration in gcc [4.8.5, ? ]
// extern const char var[]
// constexpr char var[]
#define CONSTEXPR const
#endif

#ifdef __GNUC__
#define ANSI_ESCAPE "\e["
#elif defined _MSC_VER
#define ANSI_ESCAPE "\x1b["
#endif

}  // namespace hotplace

#endif
