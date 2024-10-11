/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_NET_HTTP_HEADER_COMPRESSION__
#define __HOTPLACE_SDK_NET_HTTP_HEADER_COMPRESSION__

#include <sdk/base/basic/huffman_coding.hpp>

namespace hotplace {
namespace net {

// RFC 7541 HPACK: Header Compression for HTTP/2

enum match_result_t {
    not_matched = 0,
    /* HPACK, QPACK(static table) */
    key_matched = 1,
    all_matched = 2,
    /* QPACK(dynamic table) */
    key_matched_dynamic = 5,
    all_matched_dynamic = 6,
};
enum http_header_compression_flag_t {
    // encoding/decoding
    hpack_huffman = (1 << 0),        // RFC 7541 5.2.  String Literal Representation
    hpack_indexing = (1 << 1),       // RFC 7541 6.2.1.  Literal Header Field with Incremental Indexing
    hpack_wo_indexing = (1 << 2),    // RFC 7541 6.2.2.  Literal Header Field without Indexing
    hpack_never_indexed = (1 << 3),  // RFC 7541 6.2.3.  Literal Header Field Never Indexed

    // analysis layout while decoding
    hpack_layout_index = (1 << 4),         // RFC 7541 6.1.  Indexed Header Field Representation
    hpack_layout_indexed_name = (1 << 5),  // RFC 7541 6.2.  Literal Header Field Representation
    hpack_layout_name_value = (1 << 6),    // RFC 7541 6.2.  Literal Header Field Representation

    // encoding/decoding
    qpack_huffman = hpack_huffman,
    qpack_indexing = hpack_indexing,
    qpack_static = (1 << 7),        // RFC 9204 4.5.4.  Literal Field Line with Name Reference
    qpack_intermediary = (1 << 8),  // RFC 9204 4.5.4.  Literal Field Line with Name Reference
    qpack_postbase_index = (1 << 9),

    // analysis layout while decoding
    qpack_layout_index = (1 << 4),                     // RFC 9204 4.5.2.  Indexed Field Line
    qpack_layout_postbase_index = (1 << 11),           // RFC 9204 4.5.3.  Indexed Field Line with Post-Base Index
    qpack_layout_name_reference = (1 << 5),            // RFC 9204 4.5.4.  Literal Field Line with Name Reference
    qpack_layout_postbase_name_reference = (1 << 12),  // RFC 9204 4.5.5.  Literal Field Line with Post-Base Name Reference
    qpack_layout_name_value = (1 << 6),                // RFC 9204 4.5.6.  Literal Field Line with Literal Name
};

class http_header_compression_session;

/**
 * @brief   HTTP header compression (HPACK, QPACK)
 * @sa      hpack_encoder
 */
class http_header_compression {
   public:
    http_header_compression();

    /**
     * @brief   encode (header compression)
     * @param   http_header_compression_session* session [in] dynamic table
     * @param   binary_t& target [out]
     * @param   const std::string& name [in]
     * @param   const std::string& value [in]
     * @param   uint32 flags [inopt] see http_header_compression_flag_t
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
     */
    virtual return_t decode(http_header_compression_session* session, const byte_t* source, size_t size, size_t& pos, std::string& name, std::string& value);
    /**
     * @brief   synchronize
     * @param   http_header_compression_session* session [in] dynamic table
     * @param   binary_t& target [out]
     * @remarks
     *          // sketch
     *          qpackenc.encode
     *          qpackenc.encode
     *          qpackenc.sync -> generate the QPACK field section prefix
     */
    virtual return_t sync(http_header_compression_session* session, binary_t& target);

    /**
     * @brief   Integer Representation
     * @param   binary_t& target [out]
     * @param   uint8 mask [in]
     * @param   uint8 prefix [in]
     * @param   size_t value [in]
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
     * @remarks
     *          RFC 7541 5.2.  String Literal Representation
     *          RFC 9204 4.1.2.  String Literals
     */
    return_t decode_string(const byte_t* p, size_t& pos, uint8 flags, std::string& value);

    /**
     * @brief   dynamic table size
     * @param   binary_t& target
     * @param   uint8 maxsize
     * @remarks
     *          RFC 7541 6.3.  Dynamic Table Size Update
     *          RFC 9204 4.3.1.  Set Dynamic Table Capacity
     */
    return_t set_dynamic_table_size(binary_t& target, uint8 maxsize);
    /*
     * @brief   safe mask
     * @param   bool enable [in]
     * @sample
     *          hpack_encoder hp;
     *          binary_t bin;
     *          hp.encode(bin, 0x9f, 5, 32);                 // bad output
     *          hp.safe_mask(true).encode(bin, 0x9f, 5, 32); // overwrite mask 1001 1111 to 1000 0000
     */
    void safe_mask(bool enable);

    typedef std::pair<std::string, size_t> table_entry_t;

   protected:
    bool _safe_mask;

    typedef std::multimap<std::string, table_entry_t> static_table_t;
    typedef std::map<size_t, std::pair<std::string, std::string>> static_table_index_t;

    huffman_coding _huffcode;
    static_table_t _static_table;
    static_table_index_t _static_table_index;

    /**
     * @brief   match
     * @param   http_header_compression_session* session [in]
     * @param   uint32 flags [in]
     * @param   const std::string& name [in]
     * @param   const std::string& value [in]
     * @param   size_t& index [out]
     * @return  match_result_t
     * @remarks select index from table where name = arg(name) and value = arg(value)
     */
    match_result_t match(http_header_compression_session* session, uint32 flags, const std::string& name, const std::string& value, size_t& index);
    /**
     * @brief   select
     * @param   http_header_compression_session* session [in]
     * @param   uint32 flags [in]
     * @param   size_t index [in]
     * @param   std::string& name [out]
     * @param   std::string& value [out]
     * @remarks select name, value from table where index = arg(index)
     */
    return_t select(http_header_compression_session* session, uint32 flags, size_t index, std::string& name, std::string& value);
};

enum header_compression_cmd_t {
    hpack_cmd_size = 0,
    qpack_cmd_size = 0,
    hpack_cmd_inserted = 1,
    qpack_cmd_inserted = 1,
    hpack_cmd_dropped = 2,
    qpack_cmd_dropped = 2,
    qpack_cmd_postbase_index = 3,
    qpack_cmd_section_prefix = 4,
};

struct qpack_section_prefix_t {
    size_t ric;
    size_t base;

    qpack_section_prefix_t() : ric(0), base(0) {}
    qpack_section_prefix_t(size_t c, size_t b) : ric(c), base(b) {}
    bool sign() { return ric > base; }
};

/**
 * @brief   session
 * @sa      hpack_session, qpack_session
 */
class http_header_compression_session {
   public:
    http_header_compression_session(){};

    /**
     * @brief   match
     * @param   const std::string& name [in]
     * @param   const std::string& value [in]
     * @param   size_t& index [out]
     */
    virtual match_result_t match(const std::string& name, const std::string& value, size_t& index) = 0;
    /**
     * @brief   select
     * @param   size_t index [in]
     * @param   std::string& name [out]
     * @param   std::string& value [out]
     */
    virtual return_t select(size_t index, std::string& name, std::string& value) = 0;
    /**
     * @brief   insert
     * @param   const std::string& name [in]
     * @param   const std::string& value [in]
     */
    virtual return_t insert(const std::string& name, const std::string& value) = 0;
    /**
     * @brief   HPACK/QPACK ctrl function
     * @param   int cmd [in] see header_compression_cmd_t
     * @param   void* req [in]
     * @param   size_t reqsize [in]
     * @param   void* resp [out]
     * @param   size_t& respsize [inout]
     */
    virtual return_t ctrl(int cmd, void* req, size_t reqsize, void* resp, size_t& respsize) = 0;
};

/*
 * @brief   RFC 7541 Appendix B. Huffman Code
 * @sample
 *          huffman_coding huff;
 *          huff.imports(_h2hcodes);
 */
extern const huffman_coding::hc_code_t _h2hcodes[];

}  // namespace net
}  // namespace hotplace

#endif
