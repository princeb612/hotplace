/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_BASE_SYSTEM_TYPES__
#define __HOTPLACE_SDK_BASE_SYSTEM_TYPES__

#include <functional>
#include <hotplace/sdk/base/error.hpp>
#include <hotplace/sdk/base/stream.hpp>
#include <hotplace/sdk/base/syntax.hpp>
#include <hotplace/sdk/base/types.hpp>

namespace hotplace {

#if defined __linux__
#define DLSYM(handle, nameof_api, func_ptr) *(void **)(&func_ptr) = dlsym(handle, nameof_api)
#define TRYDLSYM(handle, nameof_api, func_ptr, branch_if_fail) \
    {                                                          \
        DLSYM(handle, nameof_api, func_ptr);                   \
        char *error = nullptr;                                 \
        if (nullptr != (error = dlerror())) {                  \
            branch_if_fail;                                    \
        }                                                      \
    }
#elif defined _WIN32 || defined _WIN64
#define DLSYM(handle, nameof_api, func_ptr) *(void **)(&func_ptr) = (void *)GetProcAddress((HMODULE)handle, nameof_api)
#define TRYDLSYM(handle, nameof_api, func_ptr, branch_if_fail) \
    {                                                          \
        DLSYM(handle, nameof_api, func_ptr);                   \
        if (nullptr == func_ptr) {                             \
            branch_if_fail;                                    \
        }                                                      \
    }
#endif

/**
 * @brief   custom unsigned integer
 * @remarks MUST sizeof(TYPE) > N
 * @example
 *          1 uint24
 *            usage cases
 *              TLS handshake length
 *              HTTP/2 frame header length
 *              ASN.1 Certificate length
 *            implement
 *              return_t b24_i32(const byte_t *p, uint8 len, uint32 &value)
 *              return_t i32_b24(byte_t *p, uint8 len, uint32 value)
 *              struct uint24_t : t_uint_custom_t<uint32, 3>
 *          2 uint40
 *            implement
 *              return_t b40_i64(const byte_t *p, uint8 len, uint64 &value)
 *              return_t i64_b40(byte_t *p, uint8 len, uint64 value)
 *              struct uint40_t : t_uint_custom_t<uint64, 5>
 *          3 uint48
 *            usage case
 *              DTLS record sequence
 *            implement
 *              return_t b48_i64(const byte_t *p, uint8 len, uint64 &value)
 *              return_t i64_b48(byte_t *p, uint8 len, uint64 value)
 *              struct uint48_t : t_uint_custom_t<uint64, 6>
 *          4 uint56
 *            implement
 *              return_t b56_i64(const byte_t *p, uint8 len, uint64 &value)
 *              return_t i64_b56(byte_t *p, uint8 len, uint64 value)
 *              struct uint56_t : t_uint_custom_t<uint64, 7>
 */
template <typename TYPE, uint8 N>
struct t_uint_custom_t {
    byte_t data[N];

    t_uint_custom_t() { memset(data, 0, N); }
    t_uint_custom_t(const t_uint_custom_t &rhs) { memcpy(data, rhs.data, N); }
    t_uint_custom_t(const byte_t *p, size_t size) {
        if (p && (size >= N)) {
            memcpy(data, p, N);
        } else {
            memset(data, 0, N);
        }
    }

    operator TYPE() {
        TYPE value = TYPE(0);
        ntoh(data, N, value);
        return value;
    }
    t_uint_custom_t &operator=(const TYPE &v) {
        set(v);
        return *this;
    }
    void set(const TYPE &v) { hton(data, N, v); }

    virtual return_t hton(byte_t *p, uint8 len, const TYPE &value) { return errorcode_t::do_nothing; }
    virtual return_t ntoh(const byte_t *p, uint8 len, TYPE &value) { return errorcode_t::do_nothing; }
};

/**
 * @brief   uint24 utility function (0 to 0x00ffffff)
 * @see     RFC 7540 4. HTTP Frames, Figure 1: Frame Layout
 *          b24_i32 - from 24bits byte stream to 32 bit integer
 *          i32_b24 - from 32 bit integer to 24bits byte stream
 */
return_t b24_i32(const byte_t *p, uint8 len, uint32 &value);
return_t i32_b24(byte_t *p, uint8 len, uint32 value);

/* TLS handshake length */
struct uint24_t : t_uint_custom_t<uint32, 3> {
    uint24_t();
    uint24_t(const uint24_t &rhs);
    uint24_t(const byte_t *p, size_t size);
    uint24_t(uint32 v);

    return_t hton(byte_t *p, uint8 len, const uint32 &value) override;
    return_t ntoh(const byte_t *p, uint8 len, uint32 &value) override;
};

return_t b24_i32(const uint24_t &u, uint32 &value);
return_t i32_b24(uint24_t &u, uint32 value);

/* DTLS record sequence */
return_t b48_i64(const byte_t *p, uint8 len, uint64 &value);
return_t i64_b48(byte_t *p, uint8 len, uint64 value);

struct uint48_t : t_uint_custom_t<uint64, 6> {
    uint48_t();
    uint48_t(const uint48_t &rhs);
    uint48_t(const byte_t *p, size_t size);
    uint48_t(uint64 v);

    return_t hton(byte_t *p, uint8 len, const uint64 &value) override;
    return_t ntoh(const byte_t *p, uint8 len, uint64 &value) override;
};

return_t b48_i64(const uint48_t &u, uint64 &value);
return_t i64_b48(uint48_t &u, uint64 value);

class critical_section;
class datetime;
class semaphore;
class signalwait_threads;
class thread;

}  // namespace hotplace

#endif
