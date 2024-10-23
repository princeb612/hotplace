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

#include <sdk/net/types.hpp>

namespace hotplace {

enum trace_category_t {
    // 0~ reserve
    category_crypto = 63,              // see category_crypto_event_t
    category_net_session = 64,         // see category_net_session_event_t
    category_http_server = 65,         // see category_http_server_event_t
    category_http_request = 66,        // see category_http_request_event_t
    category_http_response = 67,       // see category_http_response_event_t
    category_header_compression = 68,  // see category_header_compression_event_t
    category_http2_serverpush = 69,    // see category_http2_push_event_t
};

enum category_crypto_event_t {
    crypto_event_info_openssl = 1,
    crypto_event_error_openssl_load = 2,  // ex. EVP_CIPHER_fetch(EVP_get_cipherbyname), EVP_MD_fetch(EVP_get_digestbyname)
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
};

enum category_http2_push_event_t {
    http2_push_event_push_promise = 1,  // http2_serverpush::push_promise
};

/**
 * @brief   traceable
 * @remarks
 *          // sketch
 *          class object : public traceable {
 *             public:
 *              object() {}
 *              void test() {
 *                  if (istraceable()) {
 *                      basic_stream bs;
 *                      bs << "what happens here ...";
 *                      traceevent(category_http_request, 0, &bs);
 *                  }
 *              }
 *          };
 *
 *          void runtest() {
 *              object o;
 *              auto lambda = [](trace_category_t category, uint32 events, stream_t* s) -> void {};
 *              o.settrace(lambda);
 *              o.test(); // run lambda inside
 *          }
 */
class traceable {
   public:
    traceable();
    traceable(const traceable& rhs);

    /**
     * @brief   istraceable
     * @return  true/false
     */
    bool istraceable();
    /**
     * @brief   settrace
     * @param   std::function<void(trace_category_t category, uint32 events, stream_t* s)> f [in]
     */
    void settrace(std::function<void(trace_category_t category, uint32 events, stream_t* s)> f);
    /**
     * @brief   settrace
     * @param   traceable* diag [in]
     */
    void settrace(traceable* diag);
    /**
     * @brief   event
     * @param   trace_category_t category [in]
     * @param   uint32 events [in]
     * @param   stream_t* [in]
     */
    void traceevent(trace_category_t category, uint32 events, stream_t*);
    void traceevent(trace_category_t category, uint32 events, const char* fmt, ...);

   protected:
    std::function<void(trace_category_t, uint32, stream_t*)> _df;
};

}  // namespace hotplace

#endif
