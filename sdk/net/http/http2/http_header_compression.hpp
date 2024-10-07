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
    key_matched = 1,
    all_matched = 2,
};
enum hpack_flag_t {
    // encoding/decoding
    hpack_huffman = (1 << 0),
    hpack_indexing = (1 << 1),
    hpack_wo_indexing = (1 << 2),
    hpack_never_indexed = (1 << 3),

    // analysis layout while decoding
    hpack_index = (1 << 4),
    hpack_indexed_name = (1 << 5),
    hpack_name_value = (1 << 6),
};

class http_header_compression_session;

/**
 * @brief   HTTP header compression (HPACK, QPACK)
 */
class http_header_compression {
   public:
    http_header_compression();

    /**
     * @brief   Integer Representation
     * @param   binary_t& target [out]
     * @param   uint8 mask [in]
     * @param   uint8 prefix [in]
     * @param   size_t value [in]
     * @remarks
     *          RFC 7541 5.1.  Integer Representation
     *          RFC 9204 4.1.1.  Prefixed Integers
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

   protected:
    bool _safe_mask;

    typedef std::pair<std::string, size_t> table_entry_t;
    typedef std::multimap<std::string, table_entry_t> static_table_t;
    typedef std::map<size_t, std::pair<std::string, std::string>> static_table_index_t;

    huffman_coding _huffcode;
    static_table_t _static_table;
    static_table_index_t _static_table_index;

    match_result_t match(http_header_compression_session* session, const std::string& name, const std::string& value, size_t& index);
    return_t select(http_header_compression_session* session, uint32 flags, size_t index, std::string& name, std::string& value);
};

class http_header_compression_session {
   public:
    http_header_compression_session(){};

    virtual match_result_t match(const std::string& name, const std::string& value, size_t& index) = 0;
    virtual return_t select(uint32 flags, size_t index, std::string& name, std::string& value) = 0;
    virtual return_t insert(const std::string& name, const std::string& value) = 0;
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
