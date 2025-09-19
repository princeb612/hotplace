/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_NET_HTTP_HTTP3_HTTP3FRAMESETTINGS__
#define __HOTPLACE_SDK_NET_HTTP_HTTP3_HTTP3FRAMESETTINGS__

#include <hotplace/sdk/net/http/http3/http3_frame.hpp>

namespace hotplace {
namespace net {

/**
 * RFC 9114 7.2.4.  SETTINGS
 */
class http3_frame_settings : public http3_frame {
   public:
    http3_frame_settings();

    /**
     * @param uint16 id [in] see h3_settings_param_t
     * @param uint64 value [in]
     */
    http3_frame_settings& set(uint16 id, uint64 value);
    /**
     * @param uint16 id [in] see h3_settings_param_t
     * @param const binary_t& [in]
     */
    http3_frame_settings& set(uint16 id, const binary_t& value);

   protected:
    virtual return_t do_read_payload(const byte_t* stream, size_t size, size_t& pos);
    virtual return_t do_write(binary_t& bin);

   private:
    critical_section _lock;
    std::list<std::pair<uint16, variant>> _params;
};

}  // namespace net
}  // namespace hotplace

#endif
