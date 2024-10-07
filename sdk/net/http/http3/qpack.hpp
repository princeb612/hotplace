/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_NET_HTTP_HTTP3_QPACK__
#define __HOTPLACE_SDK_NET_HTTP_HTTP3_QPACK__

#include <sdk/base/basic/huffman_coding.hpp>
#include <sdk/net/http/http2/http_header_compression.hpp>

namespace hotplace {
namespace net {

// studying

class qpack_encoder : public http_header_compression {
   public:
    qpack_encoder();

    qpack_encoder& encode_name_reference(hpack_session* session, binary_t& bin, const char* name, const char* value);

   private:
};

class qpack_session : public http_header_compression_session {
   public:
    qpack_session();

    virtual match_result_t match(const std::string& name, const std::string& value, size_t& index);
    virtual return_t select(uint32 flags, size_t index, std::string& name, std::string& value);
    virtual return_t insert(const std::string& name, const std::string& value);
};

}  // namespace net
}  // namespace hotplace

#endif
