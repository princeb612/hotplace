/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_NET_HTTP_HTTP3_QPACKDYNAMICTABLE__
#define __HOTPLACE_SDK_NET_HTTP_HTTP3_QPACKDYNAMICTABLE__

#include <sdk/net/http/http3/qpack_encoder.hpp>

namespace hotplace {
namespace net {

class qpack_dynamic_table : public http2_dynamic_table {
   public:
    qpack_dynamic_table();
    virtual ~qpack_dynamic_table();

    virtual void for_each(std::function<void(size_t, size_t, const std::string&, const std::string&)> f);
    virtual void dump(const std::string& desc, std::function<void(const char*, size_t)> f);

    /**
     * @brief   QPACK query function
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
