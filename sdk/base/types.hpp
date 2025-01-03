/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_BASE_TYPES__
#define __HOTPLACE_SDK_BASE_TYPES__

#if defined __linux__
#include <sdk/base/system/linux/types.hpp>
#elif defined _WIN32 || defined _WIN64
#include <sdk/base/system/windows/types.hpp>
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

#include <sdk/base/system/windows/types.hpp>

#endif

#include <string.h>

#include <map>
#include <string>
#include <vector>

namespace hotplace {

#if defined __linux__
typedef int socket_t;
#elif defined _WIN32 || defined _WIN64
typedef SOCKET socket_t;
#endif

typedef struct sockaddr sockaddr_t;
typedef struct sockaddr_storage sockaddr_storage_t;
typedef struct linger linger_t;

#define NET_DEFAULT_TIMEOUT 10
typedef struct linger linger_t;

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
typedef std::vector<byte_t> binary_t;

struct range_t {
    size_t begin;
    size_t end;
    range_t() : begin(0), end(0) {}
    range_t(size_t b, size_t e) : begin(b), end(e) {}
    bool operator<(const range_t &rhs) const {
        bool ret = false;
        if (begin < rhs.begin) {
            ret = true;
        } else if (begin == rhs.begin) {
            ret = (end < rhs.end);
        }
        return ret;
    }
    bool operator==(const range_t &rhs) const { return (begin == rhs.begin) && (end == rhs.end); }
};

enum encoding_t {
    encoding_base16 = 1,
    encoding_base64,
    encoding_base64url,
};

#define UINT128(hi, lo) (((__uint128_t)(hi)) << 64 | (lo))

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

}  // namespace hotplace

#endif
