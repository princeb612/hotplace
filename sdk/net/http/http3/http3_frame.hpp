/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_NET_HTTP_HTTP3_HTTP3FRAME__
#define __HOTPLACE_SDK_NET_HTTP_HTTP3_HTTP3FRAME__

#include <hotplace/sdk/base/basic/variant.hpp>
#include <hotplace/sdk/base/system/critical_section.hpp>
#include <hotplace/sdk/base/system/shared_instance.hpp>
#include <hotplace/sdk/net/http/http3/types.hpp>

namespace hotplace {
namespace net {

/**
 * RFC 9114 7.  HTTP Framing Layer
 * RFC 9114 7.2.  Frame Definitions
 */
class http3_frame {
   public:
    virtual ~http3_frame();

    return_t read(const byte_t* stream, size_t size, size_t& pos);
    return_t write(binary_t& bin);

    h3_frame_t get_type();

    void addref();
    void release();

   protected:
    http3_frame(h3_frame_t type);

    return_t do_read_frame(const byte_t* stream, size_t size, size_t& pos);
    virtual return_t do_read_payload(const byte_t* stream, size_t size, size_t& pos);
    virtual return_t do_write(binary_t& bin);

    h3_frame_t _type;
    binary_t _payload;
    critical_section _lock;

   private:
    t_shared_reference<http3_frame> _shared;
};

}  // namespace net
}  // namespace hotplace

#endif
