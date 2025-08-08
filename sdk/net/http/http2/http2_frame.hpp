/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_NET_HTTP_HTTP2_HTTP2FRAME__
#define __HOTPLACE_SDK_NET_HTTP_HTTP2_HTTP2FRAME__

#include <sdk/net/http/compression/http_header_compression_stream.hpp>
#include <sdk/net/http/http2/types.hpp>
#include <sdk/net/http/types.hpp>

namespace hotplace {
namespace net {

class http2_frame {
   public:
    http2_frame();
    http2_frame(h2_frame_t type);
    http2_frame(const http2_frame_header_t& header);
    http2_frame(const http2_frame& rhs);
    virtual ~http2_frame();

    uint32 get_frame_size();
    uint32 get_payload_size();
    uint8 get_type();
    uint8 get_flags();
    uint32 get_stream_id();
    return_t get_payload(http2_frame_header_t const* header, size_t size, byte_t** payload);

    http2_frame& set_type(h2_frame_t type);
    http2_frame& set_flags(uint8 flags);
    http2_frame& set_stream_id(uint32 id);

    http2_frame& load_hpack(hpack_stream& hp);
    http2_frame& set_hpack_session(hpack_dynamic_table* session);
    hpack_dynamic_table* get_hpack_session();

    virtual return_t read(http2_frame_header_t const* header, size_t size);
    virtual return_t write(binary_t& frame);
    virtual void dump(stream_t* s);
    /**
     * @brief   read header
     * @param   const byte_t* buf [in] binary stream
     * @param   size_t size [in] size of binary stream
     * @param   std::function<void(const std::string&, const std::string&)> v [in]
     */
    virtual void read_compressed_header(const byte_t* buf, size_t size, std::function<void(const std::string&, const std::string&)> v);
    virtual void read_compressed_header(const binary_t& b, std::function<void(const std::string&, const std::string&)> v);
    /**
     * @brief   write header
     * @param   binary_t& frag [out]
     * @param   const std::string& name [in]
     * @param   const std::string& value [in]
     * @param   uint32 flags [inopt] hpack_indexing | hpack_huffman
     * @return  error code (see error.hpp)
     * @remarks HEADERS, CONTINUATION, PUSH_PROMISE fragment
     */
    virtual return_t write_compressed_header(binary_t& frag, const std::string& name, const std::string& value, uint32 flags = hpack_indexing | hpack_huffman);
    virtual return_t write_compressed_header(http_header* header, binary_t& frag, uint32 flags = hpack_indexing | hpack_huffman);

   protected:
    return_t set_payload_size(uint32 size);

   private:
    uint32 _payload_size;
    uint8 _type;
    uint8 _flags;
    uint32 _stream_id;

    hpack_dynamic_table* _hpack_dyntable;
};

extern const char constexpr_frame_length[];
extern const char constexpr_frame_type[];
extern const char constexpr_frame_flags[];
extern const char constexpr_frame_stream_identifier[];
extern const char constexpr_frame_pad_length[];
extern const char constexpr_frame_data[];
extern const char constexpr_frame_padding[];
extern const char constexpr_frame_stream_dependency[];
extern const char constexpr_frame_weight[];
extern const char constexpr_frame_fragment[];
extern const char constexpr_frame_priority[];
extern const char constexpr_frame_error_code[];
extern const char constexpr_frame_promised_stream_id[];
extern const char constexpr_frame_opaque[];
extern const char constexpr_frame_last_stream_id[];
extern const char constexpr_frame_debug_data[];
extern const char constexpr_frame_window_size_increment[];
extern const char constexpr_frame_exclusive[];
extern const char constexpr_frame_identifier[];
extern const char constexpr_frame_value[];
extern const char constexpr_frame_origin_len[];
extern const char constexpr_frame_origin[];
extern const char constexpr_frame_alt_svc_field_value[];

}  // namespace net
}  // namespace hotplace

#endif
