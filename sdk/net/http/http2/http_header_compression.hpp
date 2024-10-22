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
#include <sdk/base/unittest/traceable.hpp>
#include <sdk/net/http/http2/http_header_compression.hpp>

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

    // encoding/decoding
    qpack_huffman = hpack_huffman,
    qpack_indexing = hpack_indexing,
    qpack_static = (1 << 7),        // RFC 9204 4.5.4.  Literal Field Line with Name Reference
    qpack_intermediary = (1 << 8),  // RFC 9204 4.5.4.  Literal Field Line with Name Reference
    qpack_postbase_index = (1 << 9),
    qpack_name_reference = (1 << 5),

    // analysis layout while decoding
    hpack_layout_index = (1 << 4),         // RFC 7541 6.1.  Indexed Header Field Representation
    hpack_layout_indexed_name = (1 << 5),  // RFC 7541 6.2.  Literal Header Field Representation
    hpack_layout_name_value = (1 << 6),    // RFC 7541 6.2.  Literal Header Field Representation
    hpack_layout_capacity = (1 << 10),     // RFC 7541 6.3.  Dynamic Table Size Update

    // analysis layout while decoding
    qpack_layout_capacity = (1 << 10),       // RFC 9204 4.3.1.  Set Dynamic Table Capacity
    qpack_layout_index = (1 << 4),           // RFC 9204 4.5.2.  Indexed Field Line
    qpack_layout_name_reference = (1 << 5),  // RFC 9204 4.5.4.  Literal Field Line with Name Reference
    qpack_layout_name_value = (1 << 6),      // RFC 9204 4.5.6.  Literal Field Line with Literal Name
    qpack_layout_duplicate = (1 << 11),
    qpack_layout_ack = (1 << 12),
    qpack_layout_cancel = (1 << 13),
    qpack_layout_inc = (1 << 14),

    qpack_quic_stream_encoder = (1 << 15),  // RFC 9204 4.3.  Encoder Instructions
    qpack_quic_stream_decoder = (1 << 16),  // RFC 9204 4.4.  Decoder Instructions
    qpack_quic_stream_header = (1 << 17),   // RFC 9204 4.5.  Field Line Representations
};

enum http_header_compression_event_t {
    header_compression_event_insert = 1,
    header_compression_event_evict = 2,
};

class http_header_compression_table_static;
class http_header_compression_table_dynamic;

/**
 * @brief   HTTP header compression (HPACK, QPACK)
 * @sa      hpack_encoder
 */
class http_header_compression {
   public:
    http_header_compression();

    /**
     * @brief   encode (header compression)
     * @param   http_header_compression_table_dynamic* dyntable [in] dynamic table
     * @param   binary_t& target [out]
     * @param   const std::string& name [in]
     * @param   const std::string& value [in]
     * @param   uint32 flags [inopt] see http_header_compression_flag_t
     * @return  error code (see error.hpp)
     */
    virtual return_t encode(http_header_compression_table_dynamic* dyntable, binary_t& target, const std::string& name, const std::string& value,
                            uint32 flags = 0);
    /**
     * @brief   decode (header compression)
     * @param   http_header_compression_table_dynamic* dyntable [in] dynamic table
     * @param   const byte_t* source [in]
     * @param   size_t size [in]
     * @param   size_t& pos [in]
     * @param   std::string& name [in]
     * @param   std::string& value [in]
     * @param   uint32 flags [inopt]
     * @return  error code (see error.hpp)
     */
    virtual return_t decode(http_header_compression_table_dynamic* dyntable, const byte_t* source, size_t size, size_t& pos, std::string& name,
                            std::string& value, uint32 flags = 0);
    /**
     * @brief   synchronize
     * @param   http_header_compression_table_dynamic* dyntable [in] dynamic table
     * @param   binary_t& target [out]
     * @param   uint32 flags [inopt]
     * @return  error code (see error.hpp)
     * @remarks
     *          // sketch
     *          qpackenc.encode
     *          qpackenc.encode
     *          qpackenc.sync -> generate the QPACK field section prefix
     */
    virtual return_t sync(http_header_compression_table_dynamic* dyntable, binary_t& target, uint32 flags = 0);

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
     * @brief   dynamic table size
     * @param   http_header_compression_table_dynamic* dyntable [in]
     * @param   binary_t& target
     * @param   uint8 maxsize
     * @return  error code (see error.hpp)
     * @remarks
     *          RFC 7541 6.3.  Dynamic Table Size Update
     *          RFC 9204 4.3.1.  Set Dynamic Table Capacity
     */
    return_t set_capacity(http_header_compression_table_dynamic* dyntable, binary_t& target, uint8 maxsize);
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
     * @param   http_header_compression_table_static* static_table [in]
     * @param   http_header_compression_table_dynamic* dyntable [in]
     * @param   uint32 flags [in]
     * @param   const std::string& name [in]
     * @param   const std::string& value [in]
     * @param   size_t& index [out]
     * @return  match_result_t
     * @remarks select index from table where name = arg(name) and value = arg(value)
     */
    match_result_t matchall(http_header_compression_table_static* static_table, http_header_compression_table_dynamic* dyntable, uint32 flags,
                            const std::string& name, const std::string& value, size_t& index);
    /**
     * @brief   select
     * @param   http_header_compression_table_static* static_table [in]
     * @param   http_header_compression_table_dynamic* dyntable [in]
     * @param   uint32 flags [in]
     * @param   size_t index [in]
     * @param   std::string& name [out]
     * @param   std::string& value [out]
     * @return  error code (see error.hpp)
     * @remarks select name, value from table where index = arg(index)
     */
    return_t selectall(http_header_compression_table_static* static_table, http_header_compression_table_dynamic* dyntable, uint32 flags, size_t index,
                       std::string& name, std::string& value);

   protected:
    bool _safe_mask;
};

enum header_compression_type_t {
    header_compression_hpack = 0,
    header_compression_qpack = 1,
};

enum header_compression_cmd_t {
    hpack_cmd_inserted = 1,
    qpack_cmd_inserted = 1,
    hpack_cmd_dropped = 2,
    qpack_cmd_dropped = 2,
    qpack_cmd_postbase_index = 3,
};

/**
 * @brief   static table
 * @remarks cannot access directly, use hpack_static_table or qpack_static_table instead
 */
class http_header_compression_table_static {
   public:
    /**
     * @brief   match
     * @param   uint32 flags [in]
     * @param   const std::string& name [in]
     * @param   const std::string& value [in]
     * @param   size_t& index [out]
     * @return  error code (see error.hpp)
     */
    virtual match_result_t match(uint32 flags, const std::string& name, const std::string& value, size_t& index);
    /**
     * @brief   select
     * @param   uint32 flags [in]
     * @param   size_t index [in]
     * @param   std::string& name [out]
     * @param   std::string& value [out]
     * @return  error code (see error.hpp)
     */
    virtual return_t select(uint32 flags, size_t index, std::string& name, std::string& value);
    /**
     * @brief   size
     * @return  size of static table
     */
    virtual size_t size();

   protected:
    http_header_compression_table_static();

    virtual void load();

    typedef std::pair<std::string, size_t> table_entry_t;
    typedef std::multimap<std::string, table_entry_t> static_table_t;
    typedef std::map<size_t, std::pair<std::string, std::string>> static_table_index_t;

    critical_section _lock;
    static_table_t _static_table;
    static_table_index_t _static_table_index;
};

class hpack_static_table : public http_header_compression_table_static {
   public:
    static hpack_static_table* get_instance();

   protected:
    hpack_static_table();
    virtual void load();

    static hpack_static_table _instance;
};

class qpack_static_table : public http_header_compression_table_static {
   public:
    static qpack_static_table* get_instance();

   protected:
    qpack_static_table();
    virtual void load();

    static qpack_static_table _instance;
};

/**
 * @brief   dynamic table
 * @sa      hpack_session, qpack_session
 */
class http_header_compression_table_dynamic : public traceable {
   public:
    http_header_compression_table_dynamic();

    /**
     * @brief   for_each
     */
    void for_each(std::function<void(const std::string&, const std::string&)> v);
    /**
     * @brief   compare
     */
    bool operator==(const http_header_compression_table_dynamic& rhs);
    bool operator!=(const http_header_compression_table_dynamic& rhs);
    /**
     * @brief   trace
     */
    void trace(std::function<void(trace_category_t, uint32, stream_t*)> f);
    /**
     * @brief   match
     * @param   uint32 flags [in]
     * @param   const std::string& name [in]
     * @param   const std::string& value [in]
     * @param   size_t& index [out]
     * @return  match_result_t
     */
    virtual match_result_t match(uint32 flags, const std::string& name, const std::string& value, size_t& index);
    /**
     * @brief   select
     * @param   uint32 flags [in]
     * @param   size_t index [in]
     * @param   std::string& name [out]
     * @param   std::string& value [out]
     * @return  error code (see error.hpp)
     */
    virtual return_t select(uint32 flags, size_t index, std::string& name, std::string& value);
    /**
     * @brief   insert
     * @param   const std::string& name [in]
     * @param   const std::string& value [in]
     * @return  error code (see error.hpp)
     */
    virtual return_t insert(const std::string& name, const std::string& value);
    /**
     * @brief   evict
     * @return  error code (see error.hpp)
     */
    virtual return_t evict();
    /**
     * @brief   capacity (SETTINGS_QPACK_MAX_TABLE_CAPACITY)
     */
    void set_capacity(uint32 capacity);
    size_t get_capacity();
    /**
     * @brief   table size
     */
    size_t get_tablesize();
    /**
     * @brief   entries
     */
    size_t get_entries();
    /**
     * @brief   HPACK/QPACK query function
     * @param   int cmd [in] see header_compression_cmd_t
     * @param   void* req [in]
     * @param   size_t reqsize [in]
     * @param   void* resp [out]
     * @param   size_t& respsize [inout]
     * @return  error code (see error.hpp)
     */
    virtual return_t query(int cmd, void* req, size_t reqsize, void* resp, size_t& respsize);
    /**
     * @brief   type
     * @return  see header_compression_type_t
     */
    uint8 type();

   protected:
    typedef std::pair<std::string, size_t> table_entry_t;
    typedef std::multimap<std::string, table_entry_t> dynamic_map_t;  // table_entry_t(value, entry)
    typedef std::map<size_t, table_entry_t> dynamic_reversemap_t;     // table_entry_t(name, entry size)

    dynamic_map_t _dynamic_map;
    dynamic_reversemap_t _dynamic_reversemap;

    uint8 _type;  // see header_compression_type_t
    uint32 _capacity;
    size_t _tablesize;
    size_t _inserted;
    size_t _dropped;
};

/*
 * @brief   RFC 7541 Appendix B. Huffman Code
 * @sample
 *          huffman_coding huff;
 *          huff.imports(_h2hcodes);
 */
extern const huffman_coding::hc_code_t _h2hcodes[];
class http_huffman_coding : public huffman_coding {
   public:
    static http_huffman_coding* get_instance();

   protected:
    http_huffman_coding();

    virtual void load();

    critical_section _lock;
    static http_huffman_coding _instance;
};

}  // namespace net
}  // namespace hotplace

#endif
