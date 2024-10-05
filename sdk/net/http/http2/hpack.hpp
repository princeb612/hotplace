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

class hpack_encoder;
class hpack_session;

/**
 * @brief   HPACK
 * @sample
 *          hpack hp;
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
class hpack {
   public:
    hpack();
    ~hpack();

    /**
     * @brief   set
     * @remarks reduce repetition of the following values : session, binary, flags
     */
    hpack& set_encoder(hpack_encoder* hp);
    hpack& set_session(hpack_session* session);

    /**
     * @brief   get
     */
    hpack_encoder* get_encoder();
    hpack_session* get_session();

    /**
     * @brief   set flags for encoding
     */
    hpack& set_encode_flags(uint32 flags);
    /**
     * @brief   encode
     * @param   const std::string& name [in]
     * @param   const std::string& value [in]
     * @param   uint32 flags [inopt] if zero, follows set_encode_flags
     * @sample
     *          hpack hp;
     *          hpack_session session;
     *          hp
     *              .set_encoder(encoder)
     *              .set_session(&session)
     *              .set_encode_flags(hpack_indexing | hpack_huffman)
     *              .encode_header(name1, value1)
     *              .encode_header(name2, value2);
     *              .encode_header("content-length", "123", hpack_wo_indexing | hpack_huffman);
     */
    hpack& encode_header(const std::string& name, const std::string& value, uint32 flags = 0);
    /**
     * @brief   encoded data
     */
    binary_t& get_binary();

    /**
     * @brief   decode
     */
    hpack& decode_header(const byte_t* source, size_t size, size_t& pos, std::string& name, std::string& value);

   private:
    hpack_encoder* _encoder;
    hpack_session* _session;
    uint32 _flags;
    binary_t _bin;
};

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
    return_t hc_encode_int(binary_t& target, uint8 mask, uint8 prefix, size_t value);
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
    return_t hc_decode_int(const byte_t* p, size_t& pos, uint8 mask, uint8 prefix, size_t& value);

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
    return_t hc_encode_string(const huffman_coding& hc, binary_t& target, uint32 flags, const char* value, size_t size);
    /**
     * @brief   string literal representation
     * @param   const huffman_coding& hc [in]
     * @param   const byte_t* p [in]
     * @param   size_t& pos [inout]
     * @param   uint8 flags [in]
     * @param   std::string& value [out]
     * @remarks
     *          RFC 7541 5.2.  String Literal Representation
     *          RFC 9204 4.1.2.  String Literals
     */
    return_t hc_decode_string(const huffman_coding& hc, const byte_t* p, size_t& pos, uint8 flags, std::string& value);

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
    friend class hpack_session;

   public:
    hpack_encoder();

    /**
     * @brief   encode (header compression)
     * @param   hpack_session* session [in] dynamic table
     * @param   binary_t& target [out]
     * @param   const std::string& name [in]
     * @param   const std::string& value [in]
     * @param   uint32 flags [inopt]
     */
    hpack_encoder& encode_header(hpack_session* session, binary_t& target, const std::string& name, const std::string& value, uint32 flags = 0);
    /**
     * @brief   decode (header compression)
     * @param   hpack_session* session [in] dynamic table
     * @param   const byte_t* source [in]
     * @param   size_t size [in]
     * @param   size_t& pos [in]
     * @param   std::string& name [in]
     * @param   std::string& value [in]
     */
    hpack_encoder& decode_header(hpack_session* session, const byte_t* source, size_t size, size_t& pos, std::string& name, std::string& value);

    /**
     * @brief   integer
     * @param   binary_t& target [out]
     * @param   uint8 mask [in]
     * @param   uint8 prefix [in]
     * @param   size_t value [in]
     */
    hpack_encoder& encode_int(binary_t& target, uint8 mask, uint8 prefix, size_t value);
    /**
     * @brief   string
     * @param   binary_t& target [out]
     * @param   uint32 flags [in]
     * @param   const char* value [in]
     */
    hpack_encoder& encode_string(binary_t& target, uint32 flags, const char* value);
    /**
     * @brief   string
     * @param   binary_t& target [out]
     * @param   uint32 flags [in]
     * @param   const char* value [in]
     * @param   size_t size [in]
     */
    hpack_encoder& encode_string(binary_t& target, uint32 flags, const char* value, size_t size);
    /**
     * @brief   string
     * @param   binary_t& target [out]
     * @param   uint32 flags [in]
     * @param   const std::string& value [in]
     */
    hpack_encoder& encode_string(binary_t& target, uint32 flags, const std::string& value);
    /**
     * @brief   index
     * @param   binary_t& target [out]
     * @param   uint8 index [in]
     */
    hpack_encoder& encode_index(binary_t& target, uint8 index);
    /**
     * @bried   indexed name
     * @param   binary_t& target [out]
     * @param   uint32 flags [in]
     * @param   uint8 index [in]
     * @param   const char* value [in]
     */
    hpack_encoder& encode_indexed_name(binary_t& target, uint32 flags, uint8 index, const char* value);
    /**
     * @bried   indexed name
     * @param   binary_t& target [out]
     * @param   uint32 flags [in]
     * @param   uint8 index [in]
     * @param   const char* value [in]
     * @param   size_t size [in]
     */
    hpack_encoder& encode_indexed_name(binary_t& target, uint32 flags, uint8 index, const char* value, size_t size);
    /**
     * @bried   indexed name
     * @param   binary_t& target [out]
     * @param   uint32 flags [in]
     * @param   uint8 index [in]
     * @param   const std::string& value [in]
     */
    hpack_encoder& encode_indexed_name(binary_t& target, uint32 flags, uint8 index, const std::string& value);
    /**
     * @brief   name value
     * @param   binary_t& target [out]
     * @param   uint32 flags [in]
     * @param   const char* name [in]
     * @param   const char* value [in]
     */
    hpack_encoder& encode_name_value(binary_t& target, uint32 flags, const char* name, const char* value);
    hpack_encoder& encode_name_value(binary_t& target, uint32 flags, const char* name, size_t namelen, const char* value, size_t valuelen);
    /**
     * @brief   name value
     * @param   binary_t& target [out]
     * @param   uint32 flags [in]
     * @param   const std::string& name [in]
     * @param   const std::string& value [in]
     */
    hpack_encoder& encode_name_value(binary_t& target, uint32 flags, const std::string& name, const std::string& value);

    /**
     * @brief   integer
     * @param   const byte_t* p [in]
     * @param   size_t& pos [inout]
     * @param   uint8 mask [in]
     * @param   uint8 prefix [in]
     * @param   size_t& value [in]
     */
    hpack_encoder& decode_int(const byte_t* p, size_t& pos, uint8 mask, uint8 prefix, size_t& value);
    /**
     * @brief   string
     * @param   const byte_t* p [in]
     * @param   size_t& pos [inout]
     * @param   uint8 flags [in]
     * @param   std::string& value [out]
     */
    hpack_encoder& decode_string(const byte_t* p, size_t& pos, uint8 flags, std::string& value);

   protected:
   private:
    typedef std::pair<std::string, size_t> table_entry_t;
    typedef std::multimap<std::string, table_entry_t> static_table_t;
    typedef std::map<size_t, std::pair<std::string, std::string>> static_table_index_t;

    huffman_coding _huffcode;
    static_table_t _static_table;
    static_table_index_t _static_table_index;

    match_result_t match(hpack_session* session, const std::string& name, const std::string& value, size_t& index);
    return_t insert(hpack_session* session, const std::string& name, const std::string& value);
    return_t select(hpack_session* session, uint32 flags, size_t index, std::string& name, std::string& value);
};

/**
 * @brief   separate dynamic table per session
 * @sa      hpack_encoder
 */
class hpack_session {
    friend class hpack_encoder;

   public:
    hpack_session();
    hpack_session(const hpack_session& rhs);

    hpack_session& set_capacity(uint32 capacity);

    bool operator==(const hpack_session& rhs);
    bool operator!=(const hpack_session& rhs);
    void for_each(std::function<void(const std::string&, const std::string&)> v);

   protected:
    match_result_t match(const std::string& name, const std::string& value, size_t& index);
    return_t insert(const std::string& name, const std::string& value);
    return_t select(uint32 flags, size_t index, std::string& name, std::string& value);

   private:
    typedef hpack_encoder::table_entry_t table_entry_t;
    typedef std::list<std::pair<std::string, table_entry_t>> dynamic_table_t;
    dynamic_table_t _dynamic_table;
    uint32 _capacity;
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
