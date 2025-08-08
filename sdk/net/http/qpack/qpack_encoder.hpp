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
enum qpack_decode_flag_t {
    qpack_decode_capacity = 1 << 0,              // 0x00000001 capacity
    qpack_decode_field_section_prefix = 1 << 1,  // 0x00000002 ric, base
    qpack_decode_index = 1 << 2,                 // 0x00000004 index, name, value
    qpack_decode_nameref = 1 << 3,               // 0x00000008 index, name, value
    qpack_decode_namevalue = 1 << 4,             // 0x00000010 name, value
    qpack_decode_ack = 1 << 5,                   // 0x00000020 streamid
    qpack_decode_cancel = 1 << 6,                // 0x00000040 streamid
    qpack_decode_dup = 1 << 7,                   // 0x00000080 index, name, value
    qpack_decode_inc = 1 << 8,                   // 0x00000100 inc
};
struct qpack_decode_t {
    // qpack_decode_flag_t
    uint32 flags;
    // capacity
    size_t capacity;
    // field section prefix
    size_t ric;
    size_t base;
    // index, nameref, dup
    size_t index;
    // index, nameref, namevalue, dup
    std::string name;
    std::string value;
    // ack, cancel
    uint64 streamid;
    // inc
    size_t inc;

    qpack_decode_t() : flags(0), capacity(0), ric(0), base(0), index(0), streamid(0), inc(0) {}
    void clear() {
        flags = 0;
        capacity = 0;
        ric = 0;
        base = 0;
        index = 0;
        name.clear();
        value.clear();
        streamid = 0;
        inc = 0;
    }
};

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
     * @param   qpack_decode_t& item [out]
     * @param   uint32 flags [inopt]
     * @return  error code (see error.hpp)
     * @sample
     *          pos = 0;
     *          while (pos < streamsize) {
     *              encoder.decode(dyntable, stream, streamsize, pos, item, flags);
     *          }
     */
    virtual return_t decode(http_dynamic_table* dyntable, const byte_t* source, size_t size, size_t& pos, qpack_decode_t& item, uint32 flags = 0);
    return_t decode(http_dynamic_table* dyntable, const byte_t* source, size_t size, size_t& pos, std::list<qpack_decode_t>& kv, uint32 flags = 0);
    /**
     * @brief   RFC 9204 4.3.1.  Set Dynamic Table Capacity
     * @param   http_dynamic_table* dyntable [in]
     * @param   binary_t& target [out]
     * @param   uint64 capacity [in]
     */
    return_t encode_dyntable_capacity(http_dynamic_table* dyntable, binary_t& target, uint64 capacity);
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
    virtual return_t pack(http_dynamic_table* dyntable, binary_t& target, uint32 flags = 0);

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
     * @param   qpack_decode_t& item [out]
     */
    qpack_encoder& decode_header(http_dynamic_table* dyntable, const byte_t* source, size_t size, size_t& pos, qpack_decode_t& item);

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
    /**
     * @breif   duplicate
     * @param   binary_t& target [out]
     * @param   size_t index [in]
     * @remarks
     *          RFC 9204 4.3.  Encoder Instructions
     *          RFC 9204 4.3.4.  Duplicate
     */
    qpack_encoder& duplicate(http_dynamic_table* dyntable, binary_t& target, size_t index);
    /**
     * @breif   ack
     * @param   binary_t& target [out]
     * @param   uint32 streamid [in]
     * @remarks
     *          RFC 9204 4.4.  Decoder Instructions
     *          RFC 9204 4.4.1.  Section Acknowledgment
     */
    qpack_encoder& ack(http_dynamic_table* dyntable, binary_t& target, uint32 streamid);
    /**
     * @breif   cancel
     * @param   binary_t& target [out]
     * @param   uint32 streamid [in]
     * @remarks
     *          RFC 9204 4.4.  Decoder Instructions
     *          RFC 9204 4.4.2.  Stream Cancellation
     */
    qpack_encoder& cancel(http_dynamic_table* dyntable, binary_t& target, uint32 streamid);
    /**
     * @breif   increment
     * @param   binary_t& target [out]
     * @param   size_t inc [in]
     * @return  error code (see error.hpp)
     * @remarks
     *          RFC 9204 4.4.  Decoder Instructions
     *          RFC 9204 4.4.3.  Insert Count Increment
     */
    qpack_encoder& increment(http_dynamic_table* dyntable, binary_t& target, size_t inc);

    return_t decode_section_prefix(http_dynamic_table* dyntable, const byte_t* source, size_t size, size_t& pos, qpack_decode_t& item);

   protected:
    virtual return_t decode_encoder_stream(http_dynamic_table* dyntable, const byte_t* source, size_t size, size_t& pos, qpack_decode_t& item,
                                           uint32 flags = 0);
    virtual return_t decode_decoder_stream(http_dynamic_table* dyntable, const byte_t* source, size_t size, size_t& pos, qpack_decode_t& item,
                                           uint32 flags = 0);
    virtual return_t decode_http3_header(http_dynamic_table* dyntable, const byte_t* source, size_t size, size_t& pos, qpack_decode_t& item, uint32 flags = 0);
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
