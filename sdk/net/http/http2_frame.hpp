/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_NET_HTTP_HTTP2_FRAME__
#define __HOTPLACE_SDK_NET_HTTP_HTTP2_FRAME__

#include <sdk/base.hpp>
#include <sdk/base/stream/basic_stream.hpp>
#include <sdk/io/basic/payload.hpp>
#include <sdk/net/server/network_protocol.hpp>

namespace hotplace {
namespace net {

// studying ...

// RFC 7540 4. HTTP Frames
// RFC 7540 11.2. Frame Type Registry
enum h2_frame_t {
    h2_frame_data = 0x0,           // RFC 7540 6.1. DATA
    h2_frame_headers = 0x1,        // RFC 7540 6.2. HEADERS
    h2_frame_priority = 0x2,       // RFC 7540 6.3. PRIORITY
    h2_frame_rst_stream = 0x3,     // RFC 7540 6.4. RST_STREAM
    h2_frame_settings = 0x4,       // RFC 7540 6.5. SETTINGS
    h2_frame_push_promise = 0x5,   // RFC 7540 6.6. PUSH_PROMISE
    h2_frame_ping = 0x6,           // RFC 7540 6.7. PING
    h2_frame_goaway = 0x7,         // RFC 7540 6.8. GOAWAY
    h2_frame_window_update = 0x8,  // RFC 7540 6.9. WINDOW_UPDATE
    h2_frame_continuation = 0x9,   // RFC 7540 6.10. CONTINUATION
};

// RFC 7540 6. Frame Definitions
enum h2_flag_t {
    h2_flag_end_stream = 0x1,   // DATA, HEADERS
    h2_flag_end_headers = 0x4,  // HEADERS, PUSH_PROMISE, CONTINUATION
    h2_flag_padded = 0x8,       // DATA, HEADERS, PUSH_PROMISE
    h2_flag_priority = 0x20,    // HEADERS

    h2_flag_ack = 0x1,  // SETTINGS, PING
};

// RFC 7540 6.5.2. Defined Settings Parameters
// RFC 7540 11.3. Settings Registry
enum h2_settings_param_t {
    h2_settings_header_table_size = 0x1,       // SETTINGS
    h2_settings_enable_push = 0x2,             // SETTINGS
    h2_settings_max_concurrent_streams = 0x3,  // SETTINGS
    h2_settings_initial_window_size = 0x4,     // SETTINGS
    h2_settings_max_frame_size = 0x5,          // SETTINGS
    h2_settings_max_header_list_size = 0x6,    // SETTINGS
};

// RFC 7540 7. Error Codes
// RFC 7540 11.4. Error Code Registry
enum h2_errorcodes_t {
    h2_no_error = 0x0,
    h2_protocol_error = 0x1,
    h2_internal_error = 0x2,
    h2_flow_control_error = 0x3,
    h2_settings_timeout = 0x4,
    h2_stream_closed = 0x5,
    h2_frame_size_error = 0x6,
    h2_refused_stream = 0x7,
    h2_cancel = 0x8,
    h2_compression_error = 0x9,
    h2_connect_error = 0xa,
    h2_enhance_your_calm = 0xb,
    h2_inadequate_security = 0xc,
    h2_http_1_1_required = 0xd,
};

#pragma pack(push, 1)

// RFC 7540 6. Frame Definitionsz
typedef struct _http2_frame_header_t {
    byte_t len[3];     // length (24), 2^14, SETTINGS_MAX_FRAME_SIZE 2^24-1
    uint8 type;        // type (8)
    uint8 flags;       // flags (8)
    uint32 stream_id;  // reserved (1), stream identifier (31), client odd-number, server even-number
} http2_frame_header_t;

typedef struct _http2_setting_t {
    uint16 id;
    uint32 value;
} http2_setting_t;

typedef struct _http2_priority_t {
    uint32 dependency;
    uint8 weight;
} http2_priority_t;

typedef struct _http2_goaway_t {
    uint32 last_id;
    uint32 errorcode;
    byte_t* debug;
} http2_goaway_t;

#pragma pack(pop)

class http2_frame_header {
   public:
    http2_frame_header();
    http2_frame_header(h2_frame_t type);
    http2_frame_header(const http2_frame_header& o);
    http2_frame_header(http2_frame_header_t const& header);

    uint32 get_frame_size();
    uint32 get_payload_size();
    uint8 get_type();
    uint8 get_flags();
    uint32 get_stream_id();
    return_t get_payload(http2_frame_header_t const* header, size_t size, byte_t** payload);

    http2_frame_header& set_type(h2_frame_t type);
    http2_frame_header& set_flags(uint8 flags);
    http2_frame_header& set_stream_id(uint32 id);

    virtual return_t read(http2_frame_header_t const* header, size_t size);
    virtual return_t write(binary_t& frame);
    virtual void dump(stream_t* s);

    void set_binary(binary_t& target, byte_t* data, size_t size) {
        if (data) {
            target.clear();
            target.insert(target.end(), data, data + size);
        }
    }

   protected:
    return_t set_payload_size(uint32 size);

   private:
    uint32 _payload_size;
    uint8 _type;
    uint8 _flags;
    uint32 _stream_id;
};

// RFC 7540 6.1. DATA
// RFC 7540 Figure 6: DATA Frame Payload
class http2_data_frame : public http2_frame_header {
   public:
    http2_data_frame();

    virtual return_t read(http2_frame_header_t const* header, size_t size);
    virtual return_t write(binary_t& frame);
    virtual void dump(stream_t* s);

   private:
    uint8 _padlen;
    binary_t _data;
};

// RFC 7540 6.2 HEADERS
class http2_headers_frame : public http2_frame_header {
   public:
    http2_headers_frame();

    virtual return_t read(http2_frame_header_t const* header, size_t size);
    virtual return_t write(binary_t& frame);
    virtual void dump(stream_t* s);

   private:
    uint8 _padlen;
    bool _exclusive;
    uint32 _dependency;
    uint8 _weight;
    binary_t _fragment;
};

// RFC 7540 6.3. PRIORITY
// RFC 7540 Figure 8: PRIORITY Frame Payload
class http2_priority_frame : public http2_frame_header {
   public:
    http2_priority_frame();

    virtual return_t read(http2_frame_header_t const* header, size_t size);
    virtual return_t write(binary_t& frame);
    virtual void dump(stream_t* s);

   private:
    bool _exclusive;
    uint32 _dependency;
    uint8 _weight;
};

// RFC 7540 6.4. RST_STREAM
// RFC 7540 Figure 9: RST_STREAM Frame Payload
class http2_rst_stream_frame : public http2_frame_header {
   public:
    http2_rst_stream_frame();

    virtual return_t read(http2_frame_header_t const* header, size_t size);
    virtual return_t write(binary_t& frame);
    virtual void dump(stream_t* s);

   private:
    uint32 _errorcode;
};

// RFC 7540 6.5. SETTINGS
class http2_settings_frame : public http2_frame_header {
   public:
    http2_settings_frame();

    http2_settings_frame& add(uint16 id, uint32 value);

    virtual return_t read(http2_frame_header_t const* header, size_t size);
    virtual return_t write(binary_t& frame);
    virtual void dump(stream_t* s);

   private:
    typedef std::map<uint16, uint32> h2_setting_map_t;
    typedef std::pair<h2_setting_map_t::iterator, bool> h2_setting_map_pib_t;
    h2_setting_map_t _settings;
};

// RFC 7540 6.6. PUSH_PROMISE
class http2_push_promise_frame : public http2_frame_header {
   public:
    http2_push_promise_frame();

    virtual return_t read(http2_frame_header_t const* header, size_t size);
    virtual return_t write(binary_t& frame);
    virtual void dump(stream_t* s);

   private:
    uint8 _padlen;
    uint32 _promised_id;
    binary_t _fragment;
};

// RFC 7540 6.7. PING
class http2_ping_frame : public http2_frame_header {
   public:
    http2_ping_frame();

    virtual return_t read(http2_frame_header_t const* header, size_t size);
    virtual return_t write(binary_t& frame);
    virtual void dump(stream_t* s);

   private:
    uint64 _opaque;
};

// RFC 7540 6.8. GOAWAY
class http2_goaway_frame : public http2_frame_header {
   public:
    http2_goaway_frame();

    virtual return_t read(http2_frame_header_t const* header, size_t size);
    virtual return_t write(binary_t& frame);
    virtual void dump(stream_t* s);

   private:
    uint32 _last_id;
    uint32 _errorcode;
    binary_t _debug;
};

// RFC 7540 6.9. WINDOW_UPDATE
class http2_window_update_frame : public http2_frame_header {
   public:
    http2_window_update_frame();

    virtual return_t read(http2_frame_header_t const* header, size_t size);
    virtual return_t write(binary_t& frame);
    virtual void dump(stream_t* s);

   private:
    uint32 _increment;
};

// RFC 7540 6.10. CONTINUATION
class http2_continuation_frame : public http2_frame_header {
   public:
    http2_continuation_frame();

    virtual return_t read(http2_frame_header_t const* header, size_t size);
    virtual return_t write(binary_t& frame);
    virtual void dump(stream_t* s);

   private:
    binary_t _fragment;
};

}  // namespace net
}  // namespace hotplace

#endif
