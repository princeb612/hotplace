/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_NET_HTTP_HTTP2_HPACK__
#define __HOTPLACE_SDK_NET_HTTP_HTTP2_HPACK__

#include <sdk/net/http/http2/http_header_compression.hpp>

namespace hotplace {
namespace net {

// RFC 7541 HPACK: Header Compression for HTTP/2

class hpack_encoder;
class hpack_session;
class qpack_encoder;

/**
 * @brief   HPACK
 * @sample
 *          hpack_stream hp;
 *          hpack_session session;
 *          hp
 *              .set_encoder(encoder)
 *              .set_session(&session)
 *              .set_encode_flags(hpack_indexing | hpack_huffman)
 *              .encode_header(name1, value1)
 *              .encode_header(name2, value2);
 *          // do something dump_memory(hp.get_binary(), &bs);
 *          hp.get_binary().clear();
 */
class hpack_stream {
   public:
    hpack_stream();
    ~hpack_stream();

    /**
     * @brief   set
     * @remarks reduce repetition of the following values : session, binary, flags
     */
    hpack_stream& set_session(hpack_session* session);

    /**
     * @brief   get
     */
    hpack_session* get_session();

    /**
     * @brief   set flags for encoding
     */
    hpack_stream& set_encode_flags(uint32 flags);
    /**
     * @brief   encode
     * @param   const std::string& name [in]
     * @param   const std::string& value [in]
     * @param   uint32 flags [inopt] if zero, follows set_encode_flags
     * @sample
     *          hpack_stream hp;
     *          hpack_session session;
     *          hp
     *              .set_encoder(encoder)
     *              .set_session(&session)
     *              .set_encode_flags(hpack_indexing | hpack_huffman)
     *              .encode_header(name1, value1)
     *              .encode_header(name2, value2);
     *              .encode_header("content-length", "123", hpack_wo_indexing | hpack_huffman);
     */
    hpack_stream& encode_header(const std::string& name, const std::string& value, uint32 flags = 0);
    /**
     * @brief   encoded data
     */
    binary_t& get_binary();

    /**
     * @brief   decode
     */
    hpack_stream& decode_header(const byte_t* source, size_t size, size_t& pos, std::string& name, std::string& value);

   private:
    hpack_session* _session;
    uint32 _flags;
    binary_t _bin;
};

/**
 * @brief   RFC 7541 HPACK
 * @remarks
 *          t_shared_instance<hpack_encoder> _hpack;
 *          // RFC 7541 Appendix B. Huffman Code
 *          // RFC 7541 Appendix A.  Static Table Definition
 *          hpack_instance.make_share(new hpack_encoder); // load resources here
 *
 *              // thread #1 connection #1
 *              hpack_session session;
 *              (*hpack_instance).encode_header(&session, ...); // handle dynamic table #1
 *
 *              // thread #2 connection #2
 *              hpack_session session;
 *              (*hpack_instance).encode_header(&session, ...); // handle dynamic table #2
 *
 */
class hpack_encoder : public http_header_compression {
   public:
    hpack_encoder();

    /**
     * @brief   encode (header compression)
     * @param   http_header_compression_table_dynamic* session [in] dynamic table
     * @param   binary_t& target [out]
     * @param   const std::string& name [in]
     * @param   const std::string& value [in]
     * @param   uint32 flags [inopt] see http_header_compression_flag_t
     * @return  error code (see error.hpp)
     */
    virtual return_t encode(http_header_compression_table_dynamic* session, binary_t& target, const std::string& name, const std::string& value,
                            uint32 flags = 0);
    /**
     * @brief   decode (header compression)
     * @param   http_header_compression_table_dynamic* session [in] dynamic table
     * @param   const byte_t* source [in]
     * @param   size_t size [in]
     * @param   size_t& pos [in]
     * @param   std::string& name [in]
     * @param   std::string& value [in]
     * @return  error code (see error.hpp)
     */
    virtual return_t decode(http_header_compression_table_dynamic* session, const byte_t* source, size_t size, size_t& pos, std::string& name,
                            std::string& value);

    /**
     * @brief   encode (header compression)
     * @param   http_header_compression_table_dynamic* session [in] dynamic table
     * @param   binary_t& target [out]
     * @param   const std::string& name [in]
     * @param   const std::string& value [in]
     * @param   uint32 flags [inopt] see http_header_compression_flag_t
     */
    hpack_encoder& encode_header(http_header_compression_table_dynamic* session, binary_t& target, const std::string& name, const std::string& value,
                                 uint32 flags = 0);
    /**
     * @brief   decode (header compression)
     * @param   http_header_compression_table_dynamic* session [in] dynamic table
     * @param   const byte_t* source [in]
     * @param   size_t size [in]
     * @param   size_t& pos [in]
     * @param   std::string& name [in]
     * @param   std::string& value [in]
     */
    hpack_encoder& decode_header(http_header_compression_table_dynamic* session, const byte_t* source, size_t size, size_t& pos, std::string& name,
                                 std::string& value);

    /**
     * @brief   index
     * @param   binary_t& target [out]
     * @param   size_t index [in]
     */
    hpack_encoder& encode_index(binary_t& target, size_t index);
    /**
     * @bried   indexed name
     * @param   binary_t& target [out]
     * @param   uint32 flags [in]
     * @param   size_t index [in]
     * @param   const char* value [in]
     */
    hpack_encoder& encode_indexed_name(binary_t& target, uint32 flags, size_t index, const char* value);
    /**
     * @bried   indexed name
     * @param   binary_t& target [out]
     * @param   uint32 flags [in]
     * @param   size_t index [in]
     * @param   const char* value [in]
     * @param   size_t size [in]
     */
    hpack_encoder& encode_indexed_name(binary_t& target, uint32 flags, size_t index, const char* value, size_t size);
    /**
     * @bried   indexed name
     * @param   binary_t& target [out]
     * @param   uint32 flags [in]
     * @param   size_t index [in]
     * @param   const std::string& value [in]
     */
    hpack_encoder& encode_indexed_name(binary_t& target, uint32 flags, size_t index, const std::string& value);
    /**
     * @brief   name value
     * @param   binary_t& target [out]
     * @param   uint32 flags [in]
     * @param   const char* name [in]
     * @param   const char* value [in]
     */
    hpack_encoder& encode_name_value(binary_t& target, uint32 flags, const char* name, const char* value);
    /**
     * @brief   name value
     * @param   binary_t& target [out]
     * @param   uint32 flags [in]
     * @param   const char* name [in]
     * @param   size_t namelen [in]
     * @param   const char* value [in]
     * @param   size_t valuelen [in]
     */
    hpack_encoder& encode_name_value(binary_t& target, uint32 flags, const char* name, size_t namelen, const char* value, size_t valuelen);
    /**
     * @brief   name value
     * @param   binary_t& target [out]
     * @param   uint32 flags [in]
     * @param   const std::string& name [in]
     * @param   const std::string& value [in]
     */
    hpack_encoder& encode_name_value(binary_t& target, uint32 flags, const std::string& name, const std::string& value);
};

/**
 * @brief   separate dynamic table per session
 * @sa      hpack_encoder
 */
class hpack_session : public http_header_compression_table_dynamic {
   public:
    hpack_session();
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
