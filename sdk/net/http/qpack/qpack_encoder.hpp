/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_NET_HTTP_QPACK_QPACKENCODER__
#define __HOTPLACE_SDK_NET_HTTP_QPACK_QPACKENCODER__

#include <sdk/net/http/compression/http_dynamic_table.hpp>
#include <sdk/net/http/compression/http_header_compression.hpp>
#include <sdk/net/http/types.hpp>

namespace hotplace {
namespace net {

/**
 * RFC 9204 QPACK: Field Compression for HTTP/3
 */
class qpack_encoder : public http_header_compression {
   public:
    qpack_encoder();

    /**
     * @brief   encode (header compression)
     * @param   http_dynamic_table* dyntable [in] dynamic table
     * @param   binary_t& target [out]
     * @param   const std::string& name [in]
     * @param   const std::string& value [in]
     * @param   uint32 flags [inopt] see http_header_compression_flag_t
     * @return  error code (see error.hpp)
     * @remarks
     *          RFC 9204 4.3.  Encoder Instructions
     *          RFC 9204 4.3.2.  Insert with Name Reference
     *          RFC 9204 4.3.3.  Insert with Literal Name
     */
    virtual return_t encode(http_dynamic_table* dyntable, binary_t& target, const std::string& name, const std::string& value, uint32 flags = 0);
    /**
     * @brief   decode (header compression)
     * @param   http_dynamic_table* dyntable [in] dynamic table
     * @param   const byte_t* source [in]
     * @param   size_t size [in]
     * @param   size_t& pos [in]
     * @param   http_compression_decode_t& item [out]
     * @param   uint32 flags [inopt]
     * @return  error code (see error.hpp)
     * @sample
     *          pos = 0;
     *          while (pos < streamsize) {
     *              encoder.decode(dyntable, stream, streamsize, pos, item, flags);
     *          }
     */
    virtual return_t decode(http_dynamic_table* dyntable, const byte_t* source, size_t size, size_t& pos, http_compression_decode_t& item, uint32 flags = 0);
    return_t decode(http_dynamic_table* dyntable, const byte_t* source, size_t size, size_t& pos, std::list<http_compression_decode_t>& kv, uint32 flags = 0);
    /**
     * @brief   RFC 9204 4.3.1.  Set Dynamic Table Capacity
     * @param   http_dynamic_table* dyntable [in]
     * @param   binary_t& target [out]
     * @param   uint64 capacity [in]
     */
    virtual return_t set_capacity(http_dynamic_table* dyntable, binary_t& target, uint64 capacity);
    /**
     * @brief   encode (qpack_indexing flag)
     * @param   http_dynamic_table* dyntable [in]
     * @param   binary_t& target [out]
     * @param   const std::string& name [in]
     * @param   const std::string& value [int]
     * @param   uint32 flags [inopt]
     * @return  error code (see error.hpp)
     */
    return_t insert(http_dynamic_table* dyntable, binary_t& target, const std::string& name, const std::string& value, uint32 flags = 0);
    /**
     * @brief   Field Section Prefix
     * @param   http_dynamic_table* dyntable [in] dynamic table
     * @param   binary_t& target [out]
     * @param   uint32 flags [inopt]
     * @return  error code (see error.hpp)
     * @remarks
     *          // sketch
     *          qpackenc.encode
     *          qpackenc.encode
     *          qpackenc.pack -> generate the QPACK field section prefix
     */
    return_t pack(http_dynamic_table* dyntable, binary_t& target, uint32 flags = 0);
    return_t unpack(http_dynamic_table* dyntable, const byte_t* source, size_t size, size_t& pos, http_compression_decode_t& item);

    /**
     * @brief   encode (header compression)
     * @param   http_dynamic_table* dyntable [in] dynamic table
     * @param   binary_t& target [out]
     * @param   const std::string& name [in]
     * @param   const std::string& value [in]
     * @param   uint32 flags [inopt] see http_header_compression_flag_t
     */
    qpack_encoder& encode_header(http_dynamic_table* dyntable, binary_t& target, const std::string& name, const std::string& value, uint32 flags = 0);
    /**
     * @brief   decode (header compression)
     * @param   http_dynamic_table* dyntable [in] dynamic table
     * @param   const byte_t* source [in]
     * @param   size_t size [in]
     * @param   size_t& pos [in]
     * @param   http_compression_decode_t& item [out]
     */
    qpack_encoder& decode_header(http_dynamic_table* dyntable, const byte_t* source, size_t size, size_t& pos, http_compression_decode_t& item);

    /**
     * @breif   duplicate
     * @param   binary_t& target [out]
     * @param   size_t index [in]
     * @remarks
     *          RFC 9204 4.3.  Encoder Instructions
     *          RFC 9204 4.3.4.  Duplicate
     */
    virtual return_t duplicate(http_dynamic_table* dyntable, binary_t& target, size_t index);
    /**
     * @breif   ack
     * @param   binary_t& target [out]
     * @param   uint32 streamid [in]
     * @remarks
     *          RFC 9204 4.4.  Decoder Instructions
     *          RFC 9204 4.4.1.  Section Acknowledgment
     */
    virtual return_t ack(http_dynamic_table* dyntable, binary_t& target, uint32 streamid);
    /**
     * @breif   cancel
     * @param   binary_t& target [out]
     * @param   uint32 streamid [in]
     * @remarks
     *          RFC 9204 4.4.  Decoder Instructions
     *          RFC 9204 4.4.2.  Stream Cancellation
     */
    virtual return_t cancel(http_dynamic_table* dyntable, binary_t& target, uint32 streamid);
    /**
     * @breif   increment
     * @param   binary_t& target [out]
     * @param   size_t inc [in]
     * @return  error code (see error.hpp)
     * @remarks
     *          RFC 9204 4.4.  Decoder Instructions
     *          RFC 9204 4.4.3.  Insert Count Increment
     */
    virtual return_t increment(http_dynamic_table* dyntable, binary_t& target, size_t inc);

   protected:
    /**
     * @brief   index
     * @param   binary_t& target [out]
     * @param   uint32 flags [in] see http_header_compression_flag_t
     * @param   size_t index [in]
     */
    qpack_encoder& encode_index(binary_t& target, uint32 flags, size_t index);
    /**
     * @breif   name reference
     * @param   http_dynamic_table* dyntable [in]
     * @param   binary_t& target [out]
     * @param   uint32 flags [in] see http_header_compression_flag_t
     * @param   size_t index [in]
     * @param   const std::string& value [in]
     */
    qpack_encoder& encode_name_reference(http_dynamic_table* dyntable, binary_t& target, uint32 flags, size_t index, const std::string& value);
    /**
     * @breif   name reference
     * @param   http_dynamic_table* dyntable [in]
     * @param   binary_t& target [out]
     * @param   uint32 flags [in] see http_header_compression_flag_t
     * @param   const std::string& name [in]
     * @param   const std::string& value [in]
     */
    qpack_encoder& encode_name_value(http_dynamic_table* dyntable, binary_t& target, uint32 flags, const std::string& name, const std::string& value);

    return_t decode_encoder_stream(http_dynamic_table* dyntable, const byte_t* source, size_t size, size_t& pos, http_compression_decode_t& item,
                                   uint32 flags = 0);
    return_t decode_decoder_stream(http_dynamic_table* dyntable, const byte_t* source, size_t size, size_t& pos, http_compression_decode_t& item,
                                   uint32 flags = 0);
    return_t decode_http3_header(http_dynamic_table* dyntable, const byte_t* source, size_t size, size_t& pos, http_compression_decode_t& item,
                                 uint32 flags = 0);
};

/**
 * @brief   Field Section Prefix
 * @param   size_t capacity [in]
 * @param   size_t ric [in]
 * @param   size_t base [in]
 * @param   size_t& eic [out]
 * @param   bool& sign [out]
 * @param   size_t& deltabase [out]
 * @return  error code (see error.hpp)
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
 * @return  error code (see error.hpp)
 */
return_t qpack_eic2ric(size_t capacity, size_t tni, size_t eic, bool sign, size_t deltabase, size_t& ric, size_t& base);

}  // namespace net
}  // namespace hotplace

#endif
