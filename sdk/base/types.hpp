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

#include <algorithm>
#include <functional>
#include <map>
#include <new>
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
    bool operator==(const struct binary_t& other) { return ((size() == other.size()) && (0 == memcmp(data(), other.data(), size()))); }
};

#define LOGLEVEL_XGROUP(X)                  \
    X(loglevel_trace, 0, "TRACE", "trace")  \
    X(loglevel_debug, 2, "DEBUG", "debug")  \
    X(loglevel_info, 4, "INFO", "info")     \
    X(loglevel_warn, 6, "WARN", "warn")     \
    X(loglevel_error, 8, "ERROR", "error")  \
    X(loglevel_fatal, 10, "FATAL", "fatal") \
    X(loglevel_notice, 12, "NOTICE", "notice")

enum class loglevel_t : uint8 {
#define EXPAND_LOGLEVEL_ENUM(enum_name, enum_val, arg_upper, arg_lower) enum_name = enum_val,
    LOGLEVEL_XGROUP(EXPAND_LOGLEVEL_ENUM)
#undef EXPAND_LOGLEVEL_ENUM

        default_loglevel = loglevel_info,
};

class loglevel_helper {
   public:
    friend inline constexpr bool operator<(loglevel_t lhs, loglevel_t rhs) noexcept { return static_cast<uint8>(lhs) < static_cast<uint8>(rhs); }
    friend inline constexpr bool operator<=(loglevel_t lhs, loglevel_t rhs) noexcept { return static_cast<uint8>(lhs) <= static_cast<uint8>(rhs); }
    friend inline constexpr bool operator>(loglevel_t lhs, loglevel_t rhs) noexcept { return static_cast<uint8>(lhs) > static_cast<uint8>(rhs); }
    friend inline constexpr bool operator>=(loglevel_t lhs, loglevel_t rhs) noexcept { return static_cast<uint8>(lhs) >= static_cast<uint8>(rhs); }

    // handle command line parameter
    // -loglevel 0
    // -loglevel 2
    // -loglevel trace
    // -loglevel debug
    // -loglevel TRACE
    // -loglevel DEBUG
    // ...

    static loglevel_t to_loglevel(int value) noexcept {
        switch (value) {
#define EXPAND_LOGLEVEL_EV2EN(enum_name, enum_val, loglevel_uppercase, loglevel_lowercase) \
    case enum_val:                                                                         \
        return loglevel_t::enum_name;
            LOGLEVEL_XGROUP(EXPAND_LOGLEVEL_EV2EN)
#undef EXPAND_LOGLEVEL_EV2EN
            default:
                return loglevel_t::default_loglevel;
        }
    }

    static loglevel_t to_loglevel(const char* str) noexcept {
        if (str == nullptr) return loglevel_t::default_loglevel;

        std::string lower_str(str);
        std::transform(lower_str.begin(), lower_str.end(), lower_str.begin(), ::tolower);

        if (lower_str == "warning") lower_str = "warn";

#define EXPAND_LOGLEVEL_LC2EN(enum_name, enum_val, loglevel_uppercase, loglevel_lowercase) \
    if (lower_str == loglevel_lowercase) return loglevel_t::enum_name;
        LOGLEVEL_XGROUP(EXPAND_LOGLEVEL_LC2EN)
#undef EXPAND_LOGLEVEL_LC2EN

        return loglevel_t::default_loglevel;
    }

    static loglevel_t to_loglevel(const std::string& str) noexcept { return to_loglevel(str.c_str()); }

    static const char* to_string(loglevel_t level) noexcept {
        switch (level) {
#define EXPAND_LOGLEVEL_EN2UC(enum_name, enum_val, loglevel_uppercase, loglevel_lowercase) \
    case loglevel_t::enum_name:                                                            \
        return loglevel_uppercase;
            LOGLEVEL_XGROUP(EXPAND_LOGLEVEL_EN2UC)
#undef EXPAND_LOGLEVEL_EN2UC
            default:
                return "UNKNOWN";
        }
    }
};

#undef LOGLEVEL_XGROUP

enum class encoding_t : uint8 {
    encoding_base16 = 1,     // BASE16
    encoding_base64 = 2,     // BASE64    + /
    encoding_base64url = 3,  // BASE64URL - _ without padding
    encoding_base16rfc = 4,  // see base16_encode_rfc, base16_decode_rfc
    encoding_h2hcodes = 5,   // HTTP/2 huffman coding
};

enum encoding_flag_t : uint8 {
    encoding_notrunc = (1 << 0),
    encoding_base16_capital = (1 << 1),
};

#ifndef _WIN32  // winnt.h
#define RTL_NUMBER_OF(x) (sizeof(x) / sizeof(x[0]))
#define RTL_FIELD_TYPE(type, field) (((type*)0)->field)
#define RTL_FIELD_SIZE(type, field) (sizeof(((type*)0)->field))
#define FIELD_OFFSET(type, field) ((int32)(arch_t) & (((type*)0)->field))
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

#define ANSI_ESCAPE "\x1b["

#ifndef UNREFERENCED_PARAMETER
#define UNREFERENCED_PARAMETER(p) (void)(p)
#endif

}  // namespace hotplace

#endif
