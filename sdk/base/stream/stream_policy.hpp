/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_BASE_STREAM_STREAMPOLICY__
#define __HOTPLACE_SDK_BASE_STREAM_STREAMPOLICY__

#include <stdarg.h>
#include <string.h>

#include <hotplace/sdk/base/basic/types.hpp>
#include <hotplace/sdk/base/stream/types.hpp>
#include <hotplace/sdk/base/system/types.hpp>
#include <iostream>
#include <ostream>

namespace hotplace {

/**
 * @remarks
 *          stream_policy* pol = stream_policy::get_instance();
 *          pol->set_allocsize(1 << 5);
 *
 *          basic_stream bs;
 *          bs << "hello world";
 */
class stream_policy {
   public:
    static stream_policy* get_instance();
    stream_policy& set_allocsize(size_t allocsize);
    size_t get_allocsize();

   private:
    static stream_policy _instance;
    stream_policy();

    typedef std::map<std::string, uint32> basic_stream_policy_map_t;
    basic_stream_policy_map_t _config;
};

}  // namespace hotplace

#endif
