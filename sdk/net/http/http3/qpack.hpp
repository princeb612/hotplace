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

/**
 * @brief   Field Section Prefix
 * @param   size_t capacity [in]
 * @param   size_t ric [in]
 * @param   size_t base [in]
 * @param   size_t& eic [out]
 * @param   bool& sign [out]
 * @param   size_t& deltabase [out]
 */
return_t qpack_ric2eic(size_t capacity, size_t ric, size_t base, size_t& eic, bool& sign, size_t& deltabase);
/**
 * @brief   Field Section Prefix (reconstruct)
 * @param   size_t capacity [in]
 * @param   size_t tni [in] total number of inserts
 * @param   size_t eic [in]
 * @param   bool sign [in]
 * @param   size_t deltabase [in]
 * @param   size_t& ric [out]
 * @param   size_t& base [out]
 */
return_t qpack_eic2ric(size_t capacity, size_t tni, size_t eic, bool sign, size_t deltabase, size_t& ric, size_t& base);

class qpack_encoder : public http_header_compression {
   public:
    qpack_encoder();

    /**
     * @brief   encode (header compression)
     * @param   http_header_compression_session* session [in] dynamic table
     * @param   binary_t& target [out]
     * @param   const std::string& name [in]
     * @param   const std::string& value [in]
     * @param   uint32 flags [inopt] see http_header_compression_flag_t
     * @remarks
     *          RFC 9204 4.3.  Encoder Instructions
     *          RFC 9204 4.3.2.  Insert with Name Reference
     *          RFC 9204 4.3.3.  Insert with Literal Name
     */
    virtual return_t encode(http_header_compression_session* session, binary_t& target, const std::string& name, const std::string& value, uint32 flags = 0);
    /**
     * @brief   decode (header compression)
     * @param   http_header_compression_session* session [in] dynamic table
     * @param   const byte_t* source [in]
     * @param   size_t size [in]
     * @param   size_t& pos [in]
     * @param   std::string& name [in]
     * @param   std::string& value [in]
     * @param   uint32 flags [inopt]
     */
    virtual return_t decode(http_header_compression_session* session, const byte_t* source, size_t size, size_t& pos, std::string& name, std::string& value,
                            uint32 flags = 0);
    /**
     * @brief   encode (qpack_indexing flag)
     * @param   http_header_compression_session* session [in]
     * @param   binary_t& target [out]
     * @param   const std::string& name [in]
     * @param   const std::string& value [int]
     * @param   uint32 flags [inopt]
     */
    return_t insert(http_header_compression_session* session, binary_t& target, const std::string& name, const std::string& value, uint32 flags = 0);
    /**
     * @brief   synchronize
     * @param   http_header_compression_session* session [in] dynamic table
     * @param   binary_t& target [out]
     * @param   uint32 flags [inopt]
     * @remarks
     *          // sketch
     *          qpackenc.encode
     *          qpackenc.encode
     *          qpackenc.sync -> generate the QPACK field section prefix
     */
    virtual return_t sync(http_header_compression_session* session, binary_t& target, uint32 flags = 0);

    /**
     * @brief   encode (header compression)
     * @param   http_header_compression_session* session [in] dynamic table
     * @param   binary_t& target [out]
     * @param   const std::string& name [in]
     * @param   const std::string& value [in]
     * @param   uint32 flags [inopt] see http_header_compression_flag_t
     */
    qpack_encoder& encode_header(http_header_compression_session* session, binary_t& target, const std::string& name, const std::string& value,
                                 uint32 flags = 0);
    /**
     * @brief   decode (header compression)
     * @param   http_header_compression_session* session [in] dynamic table
     * @param   const byte_t* source [in]
     * @param   size_t size [in]
     * @param   size_t& pos [in]
     * @param   std::string& name [in]
     * @param   std::string& value [in]
     */
    qpack_encoder& decode_header(http_header_compression_session* session, const byte_t* source, size_t size, size_t& pos, std::string& name,
                                 std::string& value);

    /**
     * @brief   index
     * @param   binary_t& target [out]
     * @param   uint32 flags [in] see http_header_compression_flag_t
     * @param   size_t index [in]
     */
    qpack_encoder& encode_index(binary_t& target, uint32 flags, size_t index);
    /**
     * @breif   name reference
     * @param   http_header_compression_session* session [in]
     * @param   binary_t& target [out]
     * @param   uint32 flags [in] see http_header_compression_flag_t
     * @param   size_t index [in]
     * @param   const std::string& value [in]
     */
    qpack_encoder& encode_name_reference(http_header_compression_session* session, binary_t& target, uint32 flags, size_t index, const std::string& value);
    /**
     * @breif   name reference
     * @param   http_header_compression_session* session [in]
     * @param   binary_t& target [out]
     * @param   uint32 flags [in] see http_header_compression_flag_t
     * @param   const std::string& name [in]
     * @param   const std::string& value [in]
     */
    qpack_encoder& encode_name_value(http_header_compression_session* session, binary_t& target, uint32 flags, const std::string& name,
                                     const std::string& value);
    /**
     * @breif   duplicate
     * @param   binary_t& target [out]
     * @param   size_t index [in]
     * @remarks
     *          RFC 9204 4.3.  Encoder Instructions
     *          RFC 9204 4.3.4.  Duplicate
     */
    qpack_encoder& duplicate(binary_t& target, size_t index);
    /**
     * @breif   ack
     * @param   binary_t& target [out]
     * @param   uint32 streamid [in]
     * @remarks
     *          RFC 9204 4.4.  Decoder Instructions
     *          RFC 9204 4.4.1.  Section Acknowledgment
     */
    qpack_encoder& ack(binary_t& target, uint32 streamid);
    /**
     * @breif   cancel
     * @param   binary_t& target [out]
     * @param   uint32 streamid [in]
     * @remarks
     *          RFC 9204 4.4.  Decoder Instructions
     *          RFC 9204 4.4.2.  Stream Cancellation
     */
    qpack_encoder& cancel(binary_t& target, uint32 streamid);
    /**
     * @breif   increment
     * @param   binary_t& target [out]
     * @param   size_t inc [in]
     * @remarks
     *          RFC 9204 4.4.  Decoder Instructions
     *          RFC 9204 4.4.3.  Insert Count Increment
     */
    qpack_encoder& increment(binary_t& target, size_t inc);

   protected:
    virtual return_t decode_quic_stream_encoder(http_header_compression_session* session, const byte_t* source, size_t size, size_t& pos, std::string& name,
                                                std::string& value, uint32 flags = 0);
    virtual return_t decode_quic_stream_decoder(http_header_compression_session* session, const byte_t* source, size_t size, size_t& pos, std::string& name,
                                                std::string& value, uint32 flags = 0);
    virtual return_t decode_quic_stream_header(http_header_compression_session* session, const byte_t* source, size_t size, size_t& pos, std::string& name,
                                               std::string& value, uint32 flags = 0);
};

class qpack_session : public http_header_compression_session {
   public:
    qpack_session();
    /**
     * @brief   QPACK query function
     * @param   int cmd [in] see header_compression_cmd_t
     * @param   void* req [in]
     * @param   size_t reqsize [in]
     * @param   void* resp [out]
     * @param   size_t& respsize [inout]
     */
    virtual return_t query(int cmd, void* req, size_t reqsize, void* resp, size_t& respsize);
};

}  // namespace net
}  // namespace hotplace

#endif