/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_NET_HTTP_HTTP2_HTTP2FRAME__
#define __HOTPLACE_SDK_NET_HTTP_HTTP2_HTTP2FRAME__

#include <sdk/net/http/http2/hpack.hpp>  // hpack_stream
#include <sdk/net/http/http2/types.hpp>
#include <sdk/net/http/types.hpp>

namespace hotplace {
namespace net {

class http2_frame {
   public:
    http2_frame();
    http2_frame(h2_frame_t type);
    http2_frame(const http2_frame_header_t& header);
    http2_frame(const http2_frame& rhs);
    virtual ~http2_frame();

    uint32 get_frame_size();
    uint32 get_payload_size();
    uint8 get_type();
    uint8 get_flags();
    uint32 get_stream_id();
    return_t get_payload(http2_frame_header_t const* header, size_t size, byte_t** payload);

    http2_frame& set_type(h2_frame_t type);
    http2_frame& set_flags(uint8 flags);
    http2_frame& set_stream_id(uint32 id);

    http2_frame& load_hpack(hpack_stream& hp);
    http2_frame& set_hpack_session(hpack_dynamic_table* session);
    hpack_dynamic_table* get_hpack_session();

    virtual return_t read(http2_frame_header_t const* header, size_t size);
    virtual return_t write(binary_t& frame);
    virtual void dump(stream_t* s);
    /**
     * @brief   read header
     * @param   const byte_t* buf [in] binary stream
     * @param   size_t size [in] size of binary stream
     * @param   std::function<void(const std::string&, const std::string&)> v [in]
     */
    virtual void read_compressed_header(const byte_t* buf, size_t size, std::function<void(const std::string&, const std::string&)> v);
    virtual void read_compressed_header(const binary_t& b, std::function<void(const std::string&, const std::string&)> v);
    /**
     * @brief   write header
     * @param   binary_t& frag [out]
     * @param   const std::string& name [in]
     * @param   const std::string& value [in]
     * @param   uint32 flags [inopt] hpack_indexing | hpack_huffman
     * @return  error code (see error.hpp)
     * @remarks HEADERS, CONTINUATION, PUSH_PROMISE fragment
     */
    virtual return_t write_compressed_header(binary_t& frag, const std::string& name, const std::string& value, uint32 flags = hpack_indexing | hpack_huffman);
    virtual return_t write_compressed_header(http_header* header, binary_t& frag, uint32 flags = hpack_indexing | hpack_huffman);

   protected:
    return_t set_payload_size(uint32 size);

   private:
    uint32 _payload_size;
    uint8 _type;
    uint8 _flags;
    uint32 _stream_id;

    hpack_dynamic_table* _hpack_dyntable;
};

/**
 * @brief   data frame
 * @see
 *          RFC 7540 6.1. DATA
 *          RFC 7540 Figure 6: DATA Frame Payload
 */
class http2_frame_data : public http2_frame {
   public:
    http2_frame_data();
    http2_frame_data(const http2_frame_data& rhs);
    virtual ~http2_frame_data();

    virtual return_t read(http2_frame_header_t const* header, size_t size);
    virtual return_t write(binary_t& frame);
    virtual void dump(stream_t* s);

    void set_data(const binary_t& data);
    void set_data(const char* data, size_t size);
    const binary_t& get_data();

   private:
    uint8 _padlen;
    binary_t _data;
};

/**
 * @brief   headers frame
 * @see
 *          RFC 7540 6.2 HEADERS
 */
class http2_frame_headers : public http2_frame {
   public:
    http2_frame_headers();
    http2_frame_headers(const http2_frame_headers& rhs);
    virtual ~http2_frame_headers();

    virtual return_t read(http2_frame_header_t const* header, size_t size);
    virtual return_t write(binary_t& frame);
    virtual void dump(stream_t* s);

    void set_fragment(const binary_t& fragment);
    const binary_t& get_fragment();

   private:
    uint8 _padlen;
    bool _exclusive;
    uint32 _dependency;
    uint8 _weight;
    binary_t _fragment;
};

/**
 * @brief   priority frame
 * @see
 *          RFC 7540 6.3. PRIORITY
 *          RFC 7540 Figure 8: PRIORITY Frame Payload
 */
class http2_frame_priority : public http2_frame {
   public:
    http2_frame_priority();
    http2_frame_priority(const http2_frame_priority& rhs);
    virtual ~http2_frame_priority();

    virtual return_t read(http2_frame_header_t const* header, size_t size);
    virtual return_t write(binary_t& frame);
    virtual void dump(stream_t* s);

   private:
    bool _exclusive;
    uint32 _dependency;
    uint8 _weight;
};

/**
 * @brief   reset_stream (RS) frame
 * @see
 *          RFC 7540 6.4. RST_STREAM
 *          RFC 7540 Figure 9: RST_STREAM Frame Payload
 */
class http2_frame_rst_stream : public http2_frame {
   public:
    http2_frame_rst_stream();
    http2_frame_rst_stream(const http2_frame_rst_stream& rhs);
    virtual ~http2_frame_rst_stream();

    virtual return_t read(http2_frame_header_t const* header, size_t size);
    virtual return_t write(binary_t& frame);
    virtual void dump(stream_t* s);

   private:
    uint32 _errorcode;
};

/**
 * @brief   settings frame
 * @see
 *          RFC 7540 6.5. SETTINGS
 */
class http2_frame_settings : public http2_frame {
   public:
    http2_frame_settings();
    http2_frame_settings(const http2_frame_settings& rhs);
    virtual ~http2_frame_settings();

    http2_frame_settings& add(uint16 id, uint32 value);
    return_t find(uint16 id, uint32& value);

    virtual return_t read(http2_frame_header_t const* header, size_t size);
    virtual return_t write(binary_t& frame);
    virtual void dump(stream_t* s);

   private:
    typedef std::map<uint16, uint32> h2_setting_map_t;
    typedef std::pair<h2_setting_map_t::iterator, bool> h2_setting_map_pib_t;
    h2_setting_map_t _settings;
};

/**
 * @brief   push_promise (PP) frame
 * @see
 *          RFC 7540 6.6. PUSH_PROMISE
 */
class http2_frame_push_promise : public http2_frame {
   public:
    http2_frame_push_promise();
    http2_frame_push_promise(const http2_frame_push_promise& rhs);
    virtual ~http2_frame_push_promise();

    virtual return_t read(http2_frame_header_t const* header, size_t size);
    virtual return_t write(binary_t& frame);
    virtual void dump(stream_t* s);

    void set_fragment(const binary_t& fragment);
    const binary_t& get_fragment();

   private:
    uint8 _padlen;
    uint32 _promised_id;
    binary_t _fragment;
};

/**
 * @brief   ping frame
 * @see
 *          RFC 7540 6.7. PING
 */
class http2_frame_ping : public http2_frame {
   public:
    http2_frame_ping();
    http2_frame_ping(const http2_frame_ping& rhs);
    virtual ~http2_frame_ping();

    virtual return_t read(http2_frame_header_t const* header, size_t size);
    virtual return_t write(binary_t& frame);
    virtual void dump(stream_t* s);

   private:
    uint64 _opaque;
};

/**
 * @brief   goaway frame
 * @see
 *          RFC 7540 6.8. GOAWAY
 */
class http2_frame_goaway : public http2_frame {
   public:
    http2_frame_goaway();
    http2_frame_goaway(const http2_frame_goaway& rhs);
    virtual ~http2_frame_goaway();

    virtual return_t read(http2_frame_header_t const* header, size_t size);
    virtual return_t write(binary_t& frame);
    virtual void dump(stream_t* s);

    /**
     * @brief   set error code
     * @param   uint32 errorcode [in] see h2_errorcodes_t
     */
    http2_frame_goaway& set_errorcode(uint32 errorcode);

    void set_debug(const binary_t& debug);
    const binary_t& get_debug();

   private:
    uint32 _last_id;
    uint32 _errorcode;
    binary_t _debug;
};

/**
 * @brief   window_update frame
 * @see
 *          RFC 7540 6.9. WINDOW_UPDATE
 */
class http2_frame_window_update : public http2_frame {
   public:
    http2_frame_window_update();
    http2_frame_window_update(const http2_frame_window_update& rhs);
    virtual ~http2_frame_window_update();

    virtual return_t read(http2_frame_header_t const* header, size_t size);
    virtual return_t write(binary_t& frame);
    virtual void dump(stream_t* s);

   private:
    uint32 _increment;
};

/**
 * @brief   continuation frame
 * @see
 *          RFC 7540 6.10. CONTINUATION
 */
class http2_frame_continuation : public http2_frame {
   public:
    http2_frame_continuation();
    http2_frame_continuation(const http2_frame_continuation& rhs);
    virtual ~http2_frame_continuation();

    virtual return_t read(http2_frame_header_t const* header, size_t size);
    virtual return_t write(binary_t& frame);
    virtual void dump(stream_t* s);

    void set_fragment(const binary_t& fragment);
    const binary_t& get_fragment();

   private:
    binary_t _fragment;
};

/**
 * @brief   The ALTSVC HTTP/2 Frame
 * @see
 *          RFC 7838 4.  The ALTSVC HTTP/2 Frame
 */
class http2_frame_alt_svc : public http2_frame {
   public:
    http2_frame_alt_svc();
    http2_frame_alt_svc(const http2_frame_alt_svc& rhs);
    virtual ~http2_frame_alt_svc();

    virtual return_t read(http2_frame_header_t const* header, size_t size);
    virtual return_t write(binary_t& frame);
    virtual void dump(stream_t* s);

    void set_origin(const binary_t& origin);
    void set_altsvc(const binary_t& altsvc);
    const binary_t& get_origin();
    const binary_t& get_altsvc();

   private:
    binary_t _origin;  // Origin
    binary_t _altsvc;  // Alt-Svc-Field-Value
};

extern const char constexpr_frame_length[];
extern const char constexpr_frame_type[];
extern const char constexpr_frame_flags[];
extern const char constexpr_frame_stream_identifier[];
extern const char constexpr_frame_pad_length[];
extern const char constexpr_frame_data[];
extern const char constexpr_frame_padding[];
extern const char constexpr_frame_stream_dependency[];
extern const char constexpr_frame_weight[];
extern const char constexpr_frame_fragment[];
extern const char constexpr_frame_priority[];
extern const char constexpr_frame_error_code[];
extern const char constexpr_frame_promised_stream_id[];
extern const char constexpr_frame_opaque[];
extern const char constexpr_frame_last_stream_id[];
extern const char constexpr_frame_debug_data[];
extern const char constexpr_frame_window_size_increment[];
extern const char constexpr_frame_exclusive[];
extern const char constexpr_frame_identifier[];
extern const char constexpr_frame_value[];
extern const char constexpr_frame_origin_len[];
extern const char constexpr_frame_origin[];
extern const char constexpr_frame_alt_svc_field_value[];

}  // namespace net
}  // namespace hotplace

#endif
