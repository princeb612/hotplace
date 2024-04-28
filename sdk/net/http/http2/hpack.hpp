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
    hpack_huffman = 1 << 0,
    hpack_indexing = 1 << 1,
    hpack_wo_indexing = 1 << 2,
    hpack_never_indexed = 1 << 3,
};

class hpack_session;

/**
 * @brief   RFC 7541 HPACK
 * @remarks
 *          t_shared_instance<hpack> _hpack;
 *          // RFC 7541 Appendix B. Huffman Code
 *          // RFC 7541 Appendix A.  Static Table Definition
 *          hpack_instance.make_share(new hpack); // load resources here
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
class hpack {
    friend class hpack_session;

   public:
    hpack();

    /**
     * @brief   encode (header compression)
     */
    hpack& encode_header(hpack_session* session, binary_t& target, std::string const& name, std::string const& value, uint32 flags = 0);
    /**
     * @brief   decode (header compression)
     */
    hpack& decode_header(hpack_session* session, byte_t* source, size_t size, size_t& pos, std::string& name, std::string& value);

    hpack& encode_int(binary_t& target, uint8 mask, uint8 prefix, size_t value);

    hpack& encode_string(binary_t& target, uint32 flags, const char* value);
    hpack& encode_string(binary_t& target, uint32 flags, const char* value, size_t size);
    hpack& encode_string(binary_t& target, uint32 flags, std::string const& value);

    hpack& encode_index(binary_t& target, uint8 index);

    hpack& encode_indexed_name(binary_t& target, uint32 flags, uint8 index, const char* value);
    hpack& encode_indexed_name(binary_t& target, uint32 flags, uint8 index, const char* value, size_t size);
    hpack& encode_indexed_name(binary_t& target, uint32 flags, uint8 index, std::string const& value);

    hpack& encode_name_value(binary_t& target, uint32 flags, const char* name, const char* value);
    hpack& encode_name_value(binary_t& target, uint32 flags, std::string const& name, std::string const& value);

    hpack& encode_dyntablesize(binary_t& target, uint8 maxsize);

    return_t decode_int(byte_t* p, size_t& pos, uint8 prefix, size_t& value);

    /*
     * @brief   safe mask
     * @sample
     *          hpack hp;
     *          binary_t bin;
     *          hp.encode(bin, 0x8f, 5, 32);                 // bad output
     *          hp.safe_mask(true).encode(bin, 0x8f, 5, 32); // overwrite mask 1000 1111 to 1000 0000
     */
    hpack& safe_mask(bool enable);

   protected:
   private:
    typedef struct _http2_table_t {
        std::string value;
        size_t index;
        _http2_table_t(size_t i) : index(i) {}
        _http2_table_t(const char* v, size_t i = 0) : index(i) {
            if (v) {
                value = v;
            }
        }
        _http2_table_t(std::string const& v, size_t i) : value(v), index(i) {}
    } http2_table_t;

    typedef std::multimap<std::string, http2_table_t> static_table_t;
    typedef std::list<std::pair<std::string, http2_table_t>> dynamic_table_t;

    huffman_coding _hc;
    static_table_t _static_table;
    bool _safe_mask;

    match_result_t find_table(hpack_session* session, std::string const& name, std::string const& value, size_t& index);
    return_t insert_table(hpack_session* session, std::string const& name, std::string const& value);
};

/**
 * @brief   separate dynamic table per session
 * @sa      hpack
 */
class hpack_session {
    friend class hpack;

   public:
    hpack_session();

   protected:
    match_result_t find_table(std::string const& name, std::string const& value, size_t& index);
    return_t insert_table(std::string const& name, std::string const& value);

   private:
    typedef hpack::http2_table_t http2_table_t;
    typedef hpack::dynamic_table_t dynamic_table_t;
    dynamic_table_t _dynamic_table;
};

// RFC 7541 Appendix B. Huffman Code
extern const huffman_coding::hc_code_t _h2hcodes[];

}  // namespace net
}  // namespace hotplace

#endif
