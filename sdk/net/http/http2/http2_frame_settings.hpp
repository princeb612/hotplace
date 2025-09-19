/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_NET_HTTP_HTTP2_HTTP2FRAMESETTINGS__
#define __HOTPLACE_SDK_NET_HTTP_HTTP2_HTTP2FRAMESETTINGS__

#include <hotplace/sdk/net/http/http2/http2_frame.hpp>

namespace hotplace {
namespace net {

/**
 * @brief   settings frame
 * @see
 *          RFC 7540 6.5. SETTINGS
 */
class http2_frame_settings : public http2_frame {
   public:
    http2_frame_settings();
    http2_frame_settings(const http2_frame_settings& rhs);
    virtual ~http2_frame_settings();

    http2_frame_settings& add(uint16 id, uint32 value);
    return_t find(uint16 id, uint32& value);

    virtual void dump(stream_t* s);

   protected:
    virtual return_t do_read_body(const byte_t* stream, size_t size, size_t& pos);
    virtual return_t do_write_body(binary_t& body);

   private:
    typedef std::map<uint16, uint32> h2_setting_map_t;
    typedef std::pair<h2_setting_map_t::iterator, bool> h2_setting_map_pib_t;
    h2_setting_map_t _settings;
};

}  // namespace net
}  // namespace hotplace

#endif
