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

#include <sdk/base/error.hpp>
#include <sdk/base/stream.hpp>
#include <sdk/base/syntax.hpp>
#include <sdk/base/types.hpp>

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
 * @brief   uint24 utility function (0 to 0x00ffffff)
 * @see     RFC 7540 4. HTTP Frames, Figure 1: Frame Layout
 *          b24_i32 - from 24bits byte stream to 32 bit integer
 *          i32_b24 - from 32 bit integer to 24bits byte stream
 */
return_t b24_i32(const byte_t *p, uint8 len, uint32 &value);
return_t i32_b24(byte_t *p, uint8 len, uint32 value);

struct uint24_t {
    byte_t data[3];
};

return_t b24_i32(const uint24_t &u, uint32 &value);
return_t i32_b24(uint24_t &u, uint32 value);

}  // namespace hotplace

#endif
