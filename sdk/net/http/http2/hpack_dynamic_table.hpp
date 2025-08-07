/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_NET_HTTP_HTTP2_HPACKDYNAMICTABLE__
#define __HOTPLACE_SDK_NET_HTTP_HTTP2_HPACKDYNAMICTABLE__

#include <sdk/net/http/http2/http2_dynamic_table.hpp>

namespace hotplace {
namespace net {

/**
 * @brief   separate dynamic table per dyntable
 * @sa      hpack_encoder
 */
class hpack_dynamic_table : public http2_dynamic_table {
   public:
    hpack_dynamic_table();
    virtual ~hpack_dynamic_table();

    virtual void for_each(std::function<void(size_t, size_t, const std::string&, const std::string&)> f);
    virtual void dump(const std::string& desc, std::function<void(const char*, size_t)> f);

    /**
     * @brief   HPACK query function
     * @param   int cmd [in] see header_compression_cmd_t
     * @param   void* req [in]
     * @param   size_t reqsize [in]
     * @param   void* resp [out]
     * @param   size_t& respsize [inout]
     * @return  error code (see error.hpp)
     */
    virtual return_t query(int cmd, void* req, size_t reqsize, void* resp, size_t& respsize);
};

}  // namespace net
}  // namespace hotplace

#endif
