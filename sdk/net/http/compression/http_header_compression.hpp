/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_NET_HTTP_COMPRESSION_HTTPHEADERCOMPRESSION__
#define __HOTPLACE_SDK_NET_HTTP_COMPRESSION_HTTPHEADERCOMPRESSION__

#include <functional>
#include <queue>
#include <sdk/net/http/compression/types.hpp>
#include <sdk/net/http/types.hpp>

namespace hotplace {
namespace net {

enum http_compression_decode_flag_t {
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
struct http_compression_decode_t {
    // http_compression_decode_flag_t
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

    http_compression_decode_t() : flags(0), capacity(0), ric(0), base(0), index(0), streamid(0), inc(0) {}
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

/**
 * @brief   HTTP header compression (HPACK, QPACK)
 * @sa      hpack_encoder
 */
class http_header_compression {
   public:
    http_header_compression();

    /**
     * @brief   encode (header compression)
     * @param   http_dynamic_table* dyntable [in] dynamic table
     * @param   binary_t& target [out]
     * @param   const std::string& name [in]
     * @param   const std::string& value [in]
     * @param   uint32 flags [inopt] see http_header_compression_flag_t
     * @return  error code (see error.hpp)
     */
    virtual return_t encode(http_dynamic_table* dyntable, binary_t& target, const std::string& name, const std::string& value, uint32 flags = 0);
    /**
     * @brief   decode (header compression)
     * @param   http_dynamic_table* dyntable [in] dynamic table
     * @param   const byte_t* source [in]
     * @param   size_t size [in]
     * @param   size_t& pos [in]
     * @param   std::string& name [in]
     * @param   std::string& value [in]
     * @param   uint32 flags [inopt]
     * @return  error code (see error.hpp)
     */
    virtual return_t decode(http_dynamic_table* dyntable, const byte_t* source, size_t size, size_t& pos, std::string& name, std::string& value,
                            uint32 flags = 0);

    /**
     * @brief   Integer Representation
     * @param   binary_t& target [out]
     * @param   uint8 mask [in]
     * @param   uint8 prefix [in]
     * @param   size_t value [in]
     * @return  error code (see error.hpp)
     * @remarks
     *          RFC 7541 5.1.  Integer Representation
     *          RFC 9204 4.1.1.  Prefixed Integers
     *                           QPACK implementations MUST be able to decode integers up to and including 62 bits long.
     */
    return_t encode_int(binary_t& target, uint8 mask, uint8 prefix, size_t value);
    /**
     * @brief   Integer Representation
     * @param   const byte_t* p [in]
     * @param   size_t& pos [inout]
     * @param   uint8 mask [in]
     * @param   uint8 prefix [in]
     * @param   size_t& value [out]
     * @return  error code (see error.hpp)
     * @remarks
     *          RFC 7541 5.1.  Integer Representation
     *          RFC 9204 4.1.1.  Prefixed Integers
     */
    return_t decode_int(const byte_t* p, size_t& pos, uint8 mask, uint8 prefix, size_t& value);

    /**
     * @brief   string literal representation
     * @param   binary_t& target [out]
     * @param   uint32 flags [in]
     * @param   const char* value [in]
     * @param   size_t size [in]
     * @return  error code (see error.hpp)
     * @remarks
     *          RFC 7541 5.2.  String Literal Representation
     *          RFC 9204 4.1.2.  String Literals
     */
    return_t encode_string(binary_t& target, uint32 flags, const char* value, size_t size);
    return_t encode_string(binary_t& target, uint32 flags, const std::string& value);
    /**
     * @brief   string literal representation
     * @param   const byte_t* p [in]
     * @param   size_t& pos [inout]
     * @param   uint8 flags [in]
     * @param   std::string& value [out]
     * @return  error code (see error.hpp)
     * @remarks
     *          RFC 7541 5.2.  String Literal Representation
     *          RFC 9204 4.1.2.  String Literals
     */
    return_t decode_string(const byte_t* p, size_t& pos, uint8 flags, std::string& value);

    /**
     * @brief   name reference
     * @param   const byte_t* p [in]
     * @param   size_t& pos [inout]
     * @param   uint8 flags [in]
     * @param   uint8 mask [in]
     * @param   uint8 prefix [in]
     * @param   std::string& name [out]
     * @return  error code (see error.hpp)
     */
    return_t decode_name_reference(const byte_t* p, size_t& pos, uint8 flags, uint8 mask, uint8 prefix, std::string& name);

    /**
     * @brief   size of entry
     * @param   const std::string& name [in]
     * @param   const std::string& value [in]
     * @param   size_t& size [out]
     * @return  error code (see error.hpp)
     * @remarks
     *          RFC 7541 4.1.  Calculating Table Size
     *          RFC 9204 3.2.1.  Dynamic Table Size
     */
    static return_t sizeof_entry(const std::string& name, const std::string& value, size_t& size);
    /*
     * @brief   safe mask
     * @param   bool enable [in]
     * @return  error code (see error.hpp)
     * @sample
     *          hpack_encoder hp;
     *          binary_t bin;
     *          hp.encode(bin, 0x9f, 5, 32);                 // bad output
     *          hp.safe_mask(true).encode(bin, 0x9f, 5, 32); // overwrite mask 1001 1111 to 1000 0000
     */
    void safe_mask(bool enable);

    /**
     * @brief   match
     * @param   http_static_table* static_table [in]
     * @param   http_dynamic_table* dyntable [in]
     * @param   uint32 flags [in]
     * @param   const std::string& name [in]
     * @param   const std::string& value [in]
     * @param   size_t& index [out]
     * @return  match_result_t
     * @remarks select index from table where name = arg(name) and value = arg(value)
     */
    match_result_t matchall(http_static_table* static_table, http_dynamic_table* dyntable, uint32 flags, const std::string& name, const std::string& value,
                            size_t& index);
    /**
     * @brief   select
     * @param   http_static_table* static_table [in]
     * @param   http_dynamic_table* dyntable [in]
     * @param   uint32 flags [in]
     * @param   size_t index [in]
     * @param   std::string& name [out]
     * @param   std::string& value [out]
     * @return  error code (see error.hpp)
     * @remarks select name, value from table where index = arg(index)
     */
    return_t selectall(http_static_table* static_table, http_dynamic_table* dyntable, uint32 flags, size_t index, std::string& name, std::string& value);

    virtual return_t set_capacity(http_dynamic_table* dyntable, binary_t& target, uint8 maxsize);
    virtual return_t duplicate(http_dynamic_table* dyntable, binary_t& target, size_t index);
    virtual return_t ack(http_dynamic_table* dyntable, binary_t& target, uint32 streamid);
    virtual return_t cancel(http_dynamic_table* dyntable, binary_t& target, uint32 streamid);
    virtual return_t increment(http_dynamic_table* dyntable, binary_t& target, size_t inc);
    virtual return_t pack(http_dynamic_table* dyntable, binary_t& target, uint32 flags = 0);

   protected:
   private:
    bool _safe_mask;
};

}  // namespace net
}  // namespace hotplace

#endif
