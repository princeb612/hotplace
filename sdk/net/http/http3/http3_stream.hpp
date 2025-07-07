/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_NET_HTTP_HTTP3_HTTP3STREAM__
#define __HOTPLACE_SDK_NET_HTTP_HTTP3_HTTP3STREAM__

#include <sdk/base/system/critical_section.hpp>
#include <sdk/base/system/shared_instance.hpp>
#include <sdk/net/http/http3/types.hpp>

namespace hotplace {
namespace net {

class http3_stream {
   public:
    http3_stream();

    return_t read(const byte_t* stream, size_t size, size_t& pos);
    return_t write(binary_t& bin);

    void addref();
    void release();

   private:
    t_shared_reference<http3_stream> _shared;

    h3_stream_t _type;
};

}  // namespace net
}  // namespace hotplace

#endif
