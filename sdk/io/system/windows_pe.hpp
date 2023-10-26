/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 * 2023.08.15   Soo Han, Kin        added : stopwatch
 */

#ifndef __HOTPLACE_SDK_IO_SYSTEM_WINDOWSPE__
#define __HOTPLACE_SDK_IO_SYSTEM_WINDOWSPE__

#include <sdk/base.hpp>
#if defined __linux__
#include <sdk/io/system/linux/winnt.hpp>
#elif defined _WIN32
#include <winnt.h>
#endif

namespace hotplace {
namespace io {

class winpe_checksum {
   public:
    winpe_checksum();
    ~winpe_checksum();

    return_t init();
    return_t update(byte_t* data, size_t size);
    return_t finalize(uint32& checksum);

   protected:
    uint32 _checksum;
    uint32 _size;
};

}  // namespace io
}  // namespace hotplace

#endif
