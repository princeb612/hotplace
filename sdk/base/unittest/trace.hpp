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

#ifndef __HOTPLACE_SDK_BASE_UNITTEST_TRACE__
#define __HOTPLACE_SDK_BASE_UNITTEST_TRACE__

#include <functional>
#include <list>
#include <sdk/base/basic/types.hpp>
#include <sdk/base/system/critical_section.hpp>
#include <sdk/base/trace.hpp>

namespace hotplace {

enum trace_category_t {
    trace_category_internal = 0,
    trace_category_crypto = 65,
    trace_category_net = 66,
};

enum trace_event_internal_t {
    trace_event_internal = 0,
    trace_event_backtrace = 1,
    trace_event_multiplexer = 2,
    trace_event_socket = 3,
};

enum trace_event_crypto_t {
    trace_event_openssl_info = 1,       // OpenSSL_version_num
    trace_event_openssl_nosupport = 2,  // ex. EVP_CIPHER_fetch(EVP_get_cipherbyname), EVP_MD_fetch(EVP_get_digestbyname)
    trace_event_encryption = 4,
    trace_event_decryption = 5,
    trace_event_digest = 6,
    trace_event_mac = 7,
    trace_event_jose_encryption = 8,
    trace_event_jose_signing = 9,
    trace_event_cose_keydistribution = 11,
    trace_event_cose_encryption = 12,
    trace_event_cose_signing = 13,
    trace_event_cose_mac = 14,
};

enum trace_event_net_t {
    trace_event_net_produce = 1,                // producer
    trace_event_net_consume = 2,                // consumer
    trace_event_net_request = 3,                // request
    trace_event_net_response = 4,               // response
    trace_event_header_compression_insert = 5,  // insertion
    trace_event_header_compression_evict = 6,   // eviction
    trace_event_header_compression_select = 7,  // select
    trace_event_http2_push_promise = 8,         // http/2 push_promise
    trace_event_openssl_tls_state = 9,          // SSL_ST_CONNECT/SSL_ST_ACCEPT/SSL_CB_READ/SSL_CB_WRITE/SSL_CB_HANDSHAKE_START/SSL_CB_HANDSHAKE_DONE/...
    trace_event_tls_protection = 10,            //
    trace_event_tls_record = 11,                //
    trace_event_tls_handshake = 12,             //
    trace_event_tls_extension = 13,             //
    trace_event_quic_packet = 14,               //
    trace_event_quic_frame = 15,                //
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
 *              trace_debug_event(trace_category_internal, 0, &bs);
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
/**
 * @brief trace (only debug build)
 */
bool istraceable();
bool istraceable(trace_category_t category);
/**
 * @remarks the higher level, the more informations
 * @param int8 level [in] see loglevel_t
 *                        loglevel_trace(0)
 *                        loglevel_debug(2)
 * @sample
 *          if (check_trace_level(loglevel_debug) && istraceable()) { do_something(); }
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
