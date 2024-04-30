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

#include <sdk/base.hpp>

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
     * @brief   encode
     */
    hpack& set_encode_flags(uint32 flags);
    hpack& encode_header(std::string const& name, std::string const& value);
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
class hpack_encoder {
    friend class hpack_session;

   public:
    hpack_encoder();

    /**
     * @brief   encode (header compression)
     */
    hpack_encoder& encode_header(hpack_session* session, binary_t& target, std::string const& name, std::string const& value, uint32 flags = 0);
    /**
     * @brief   decode (header compression)
     */
    hpack_encoder& decode_header(hpack_session* session, const byte_t* source, size_t size, size_t& pos, std::string& name, std::string& value);

    hpack_encoder& encode_int(binary_t& target, uint8 mask, uint8 prefix, size_t value);

    hpack_encoder& encode_string(binary_t& target, uint32 flags, const char* value);
    hpack_encoder& encode_string(binary_t& target, uint32 flags, const char* value, size_t size);
    hpack_encoder& encode_string(binary_t& target, uint32 flags, std::string const& value);

    hpack_encoder& encode_index(binary_t& target, uint8 index);

    hpack_encoder& encode_indexed_name(binary_t& target, uint32 flags, uint8 index, const char* value);
    hpack_encoder& encode_indexed_name(binary_t& target, uint32 flags, uint8 index, const char* value, size_t size);
    hpack_encoder& encode_indexed_name(binary_t& target, uint32 flags, uint8 index, std::string const& value);

    hpack_encoder& encode_name_value(binary_t& target, uint32 flags, const char* name, const char* value);
    hpack_encoder& encode_name_value(binary_t& target, uint32 flags, std::string const& name, std::string const& value);

    hpack_encoder& encode_dyntablesize(binary_t& target, uint8 maxsize);

    return_t decode_int(const byte_t* p, size_t& pos, uint8 mask, uint8 prefix, size_t& value);
    return_t decode_string(const byte_t* p, size_t& pos, uint8 flags, std::string& value);

    /*
     * @brief   safe mask
     * @sample
     *          hpack_encoder hp;
     *          binary_t bin;
     *          hp.encode(bin, 0x9f, 5, 32);                 // bad output
     *          hp.safe_mask(true).encode(bin, 0x9f, 5, 32); // overwrite mask 1001 1111 to 1000 0000
     */
    hpack_encoder& safe_mask(bool enable);

   protected:
   private:
    typedef std::pair<std::string, size_t> table_entry_t;
    typedef std::multimap<std::string, table_entry_t> static_table_t;
    typedef std::map<size_t, std::pair<std::string, std::string>> static_table_index_t;

    huffman_coding _hc;
    static_table_t _static_table;
    static_table_index_t _static_table_index;
    bool _safe_mask;

    match_result_t match(hpack_session* session, std::string const& name, std::string const& value, size_t& index);
    return_t insert(hpack_session* session, std::string const& name, std::string const& value);
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

   protected:
    match_result_t match(std::string const& name, std::string const& value, size_t& index);
    return_t insert(std::string const& name, std::string const& value);
    return_t select(uint32 flags, size_t index, std::string& name, std::string& value);

   private:
    typedef hpack_encoder::table_entry_t table_entry_t;
    typedef std::list<std::pair<std::string, table_entry_t>> dynamic_table_t;
    dynamic_table_t _dynamic_table;
};

// RFC 7541 Appendix B. Huffman Code
extern const huffman_coding::hc_code_t _h2hcodes[];

}  // namespace net
}  // namespace hotplace

#endif
