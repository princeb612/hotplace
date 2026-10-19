/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   redirection.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_BASE_SYSTEM_REDIRECTION__
#define __HOTPLACE_SDK_BASE_SYSTEM_REDIRECTION__

#include <hotplace/sdk/base/basic/types.hpp>

namespace hotplace {

class redirection_t {
   public:
    virtual ~redirection_t() {}
    virtual size_t read_stdout(void* buffer, size_t size) = 0;
    virtual size_t write_stdin(const void* data, size_t size) = 0;
    virtual void close() = 0;
};

}  // namespace hotplace

#if defined _WIN32 || defined _WIN64
#include <hotplace/sdk/base/system/windows/redirection.hpp>
#elif defined __linux__
#include <hotplace/sdk/base/system/linux/redirection.hpp>
#endif

#endif
