/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 */

#ifndef __HOTPLACE_SDK_BASE_UNITTEST_TRACEABLE__
#define __HOTPLACE_SDK_BASE_UNITTEST_TRACEABLE__

#include <functional>
#include <list>
#include <sdk/base/basic/types.hpp>
#include <sdk/base/system/critical_section.hpp>
#include <sdk/base/trace.hpp>

namespace hotplace {

enum trace_category_t {
    category_debug_internal = 0,
    category_base = 63,    // see category_base_t
    category_io = 64,      // see category_io_t
    category_crypto = 65,  // see category_crypto_event_t
    category_net = 66,     // see category_net_t
};

enum category_base_t {
    //
};

enum category_io_t {
    //
};

enum category_crypto_event_t {
    crypto_event_openssl_info = 1,       // OpenSSL_version_num
    crypto_event_openssl_nosupport = 2,  // ex. EVP_CIPHER_fetch(EVP_get_cipherbyname), EVP_MD_fetch(EVP_get_digestbyname)
    crypto_event_openssl_tls_state = 3,  // SSL_ST_CONNECT/SSL_ST_ACCEPT/SSL_CB_READ/SSL_CB_WRITE/SSL_CB_HANDSHAKE_START/SSL_CB_HANDSHAKE_DONE/...
    crypto_event_jose = 4,
    crypto_event_cose = 5,
};

enum category_net_t {
    net_event_netsession_produce = 1,         // network_session::produce
    net_event_netsession_consume_http2 = 2,   // http2_session::consume
    net_event_httpserver_consume = 3,         // http_server_consume
    net_event_httpresponse = 4,               // http_response::get_response
    net_event_header_compression_insert = 5,  // insertion
    net_event_header_compression_evict = 6,   // eviction
    net_event_header_compression_select = 7,  // select
    net_event_http2_push_promise = 8,         // http2_serverpush::push_promise
    net_event_tls_read = 9,
    net_event_tls_write = 10,
    net_event_tls_dump = 11,
    net_event_quic_read = 12,
    net_event_quic_write = 13,
    net_event_quic_dump = 14,
};

/**
 * @brief trace/debug
 * @sample
 *          void debug_handler(trace_category_t category, uint32 event, stream_t* s) {
 *              std::string ct;
 *              std::string ev;
 *              basic_stream bs;
 *              auto advisor = trace_advisor::get_instance();
 *              advisor->get_names(category, event, ct, ev);
 *              bs.printf("[%s][%s]%.*s", ct.c_str(), ev.c_str(), (unsigned int)s->size(), s->data());
 *              _logger->writeln(bs);
 *          };
 *
 *          void myfunction() {
 *              // do something
 *              basic_stream bs;
 *              bs = "blah blah\n";
 *              trace_debug_event(category_debug_internal, 0, &bs);
 *          }
 *
 *          set_trace_option(trace_debug);
 *          set_trace_debug(handler);
 */
void set_trace_debug(std::function<void(trace_category_t category, uint32 event, stream_t* s)> f);
void trace_debug_event(trace_category_t category, uint32 event, stream_t* s);
void trace_debug_event(trace_category_t category, uint32 event, const char* fmt, ...);
void trace_debug_filter(trace_category_t category, bool filter);
bool trace_debug_filtered(trace_category_t category);
bool istraceable();
bool istraceable(trace_category_t category);
/**
 * @remarks the higher level, the more informations
 * @sample
 *          if (check_trace_level(0) && istraceable()) { do_something(); }
 */
bool check_trace_level(int8 level);
void set_trace_level(int8 level);

/**
 * @sample
 *          std::string ct;
 *          std::string ev;
 *          basic_stream bs;
 *          auto advisor = trace_advisor::get_instance();
 *          advisor->get_names(category, event, ct, ev);
 */
class trace_advisor {
   public:
    static trace_advisor* get_instance();
    void load();

    std::string nameof_category(trace_category_t category);
    void get_names(trace_category_t category, uint32 event, std::string& cvalue, std::string& evalue);

   protected:
    trace_advisor();

   private:
    critical_section _lock;
    static trace_advisor _instance;

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
