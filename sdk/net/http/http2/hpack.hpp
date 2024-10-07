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
 * PERFORMANCE_HPACK_DYNAMIC_TABLE_USING_MAP
 * 0 simple implementation using std::list
 * 1 faster select/match using std::multimap
 */
#define PERFORMANCE_HPACK_DYNAMIC_TABLE_USING_MAP 1

/**
 * @brief   separate dynamic table per session
 * @sa      hpack_encoder
 */
class hpack_session : public http_header_compression_session {
   public:
    hpack_session();
    hpack_session(const hpack_session& rhs);

    hpack_session& set_capacity(uint32 capacity);

    bool operator==(const hpack_session& rhs);
    bool operator!=(const hpack_session& rhs);
    void for_each(std::function<void(const std::string&, const std::string&)> v);

    virtual match_result_t match(const std::string& name, const std::string& value, size_t& index);
    virtual return_t select(uint32 flags, size_t index, std::string& name, std::string& value);
    virtual return_t insert(const std::string& name, const std::string& value);

   private:
    uint32 _capacity;

    typedef hpack_encoder::table_entry_t table_entry_t;
#if PERFORMANCE_HPACK_DYNAMIC_TABLE_USING_MAP
    typedef std::multimap<std::string, table_entry_t> dynamic_map_t;
    typedef std::map<size_t, std::string> dynamic_reversemap_t;
    dynamic_map_t _dynamic_map;
    dynamic_reversemap_t _dynamic_reversemap;
    uint32 _inserted;
    uint32 _dropped;
#else
    typedef std::list<std::pair<std::string, table_entry_t> > dynamic_table_t;
    dynamic_table_t _dynamic_table;
#endif
};

}  // namespace net
}  // namespace hotplace

#endif
