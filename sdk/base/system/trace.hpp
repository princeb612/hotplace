/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_BASE_SYSTEM_TRACE__
#define __HOTPLACE_SDK_BASE_SYSTEM_TRACE__

#include <functional>
#include <sdk/base/charset.hpp>
#include <sdk/base/error.hpp>
#include <sdk/base/stream.hpp>
#include <sdk/base/syntax.hpp>
#include <sdk/base/system/critical_section.hpp>
#include <sdk/base/types.hpp>

namespace hotplace {

enum trace_option_t {
    trace_bt = 1,
    trace_except = 2,
    trace_debug = 3,
};

enum trace_category_t {
    category_debug_internal = 0,
    category_crypto = 63,              // see category_crypto_event_t
    category_net_session = 64,         // see category_net_session_event_t
    category_http_server = 65,         // see category_http_server_event_t
    category_http_request = 66,        // see category_http_request_event_t
    category_http_response = 67,       // see category_http_response_event_t
    category_header_compression = 68,  // see category_header_compression_event_t
    category_http2_serverpush = 69,    // see category_http2_push_event_t
    category_tls1 = 70,
};

enum category_crypto_event_t {
    crypto_event_info_openssl = 1,       // OpenSSL_version_num
    crypto_event_openssl_nosupport = 2,  // ex. EVP_CIPHER_fetch(EVP_get_cipherbyname), EVP_MD_fetch(EVP_get_digestbyname)
    crypto_event_state_ossl_tls = 3,     // SSL_ST_CONNECT/SSL_ST_ACCEPT/SSL_CB_READ/SSL_CB_WRITE/SSL_CB_HANDSHAKE_START/SSL_CB_HANDSHAKE_DONE/...
};

enum category_net_session_event_t {
    net_session_event_produce = 1,        // network_session::produce
    net_session_event_http2_consume = 2,  // http2_session::consume
};

enum category_http_server_event_t {
    http_server_event_consume = 1,  // http_server_consume
};

enum category_http_request_event_t {};

enum category_http_response_event_t {
    http_response_event_getresponse = 1,  // http_response::get_response
};

enum category_header_compression_event_t {
    header_compression_event_insert = 1,  // insertion
    header_compression_event_evict = 2,   // eviction
    header_compression_event_select = 3,  // select
};

enum category_http2_push_event_t {
    http2_push_event_push_promise = 1,  // http2_serverpush::push_promise
};

enum category_tls_event_t {
    tls_event_read = 1,
    tls_event_write = 2,
};

uint32 set_trace_option(uint32 option);
uint32 get_trace_option();

return_t trace_backtrace(return_t errorcode);

void set_trace_exception();
void reset_trace_exception();

/**
 * @sample
 *          // prepare
 *          set_trace_debug(handler);
 *          void myfunction() {
 *              // do something
 *              basic_stream bs;
 *              bs = "blah blah";
 *              trace_debug_event(category_debug_internal, 0, &bs);
 *          }
 *
 *          // and then activate ...
 *          set_trace_option(trace_debug);
 */
void set_trace_debug(std::function<void(trace_category_t category, uint32 event, stream_t* s)> f);
void trace_debug_event(trace_category_t category, uint32 event, stream_t* s);

class trace_advisor {
   public:
    static trace_advisor* get_instance();
    void load();

    std::string nameof_category(trace_category_t category);
    void get_names(trace_category_t category, uint32 event, std::string& cvalue, std::string& evalue);

   protected:
    trace_advisor();

    critical_section _lock;
    static trace_advisor _instance;

   private:
    typedef std::map<uint32, std::string> event_map_t;
    struct events {
        std::string cname;
        event_map_t event_map;
    };
    typedef std::map<trace_category_t, events> resource_map_t;
    resource_map_t _resource_map;
};

}  // namespace hotplace

#endif
