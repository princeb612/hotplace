/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_IO_SYSTEM_TYPES__
#define __HOTPLACE_SDK_IO_SYSTEM_TYPES__

#include <sdk/base/system/types.hpp>
#include <sdk/io/types.hpp>

namespace hotplace {
namespace io {

#if defined __SIZEOF_INT128__

int128 atoi128(const std::string& in);
uint128 atou128(const std::string& in);

#endif

/**
 * @brief   uint24 utility class (0 to 0x00ffffff)
 * @see     RFC 7540 4. HTTP Frames, Figure 1: Frame Layout
 */
class uint32_24_t {
   public:
    uint32_24_t();
    uint32_24_t(byte_t* p, size_t size);
    uint32_24_t(uint24_t value);
    uint32_24_t(uint32 value);

    operator uint32();
    uint32 get();
    return_t set(uint24_t value);
    return_t set(uint32 value);

    uint32_24_t& operator=(uint32 value);

   private:
    uint24_t _value;
};

}  // namespace io
}  // namespace hotplace

#endif
