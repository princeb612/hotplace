/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   trace.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_BASE_TRACE__
#define __HOTPLACE_SDK_BASE_TRACE__

#include <functional>

namespace hotplace {

enum class trace_category_t : uint32 {
    trace_category_internal = 0,
    trace_category_crypto = 0x100,
    trace_category_net = 0x200,
};

enum class trace_event_t : uint32 {
    trace_event_internal = static_cast<uint32>(trace_category_t::trace_category_internal),
    trace_event_backtrace,
    trace_event_multiplexer,
    trace_event_socket,

    trace_event_crypto_general = static_cast<uint32>(trace_category_t::trace_category_crypto),
    trace_event_openssl_info,       // OpenSSL_version_num
    trace_event_openssl_nosupport,  // ex. EVP_CIPHER_fetch(EVP_get_cipherbyname), EVP_MD_fetch(EVP_get_digestbyname)
    trace_event_encryption,
    trace_event_decryption,
    trace_event_digest,
    trace_event_mac,
    trace_event_jose_encryption,
    trace_event_jose_signing,
    trace_event_cose_keydistribution,
    trace_event_cose_encryption,
    trace_event_cose_signing,
    trace_event_cose_mac,
    trace_event_keyexchange,
    trace_event_verify,

    trace_event_net_general = static_cast<uint32>(trace_category_t::trace_category_net),
    trace_event_net_produce,                // producer
    trace_event_net_consume,                // consumer
    trace_event_net_request,                // request
    trace_event_net_response,               // response
    trace_event_header_compression_insert,  // insertion
    trace_event_header_compression_evict,   // eviction
    trace_event_header_compression_select,  // select
    trace_event_http2_push_promise,         // http/2 push_promise
    trace_event_openssl_tls_state,          // SSL_ST_CONNECT/SSL_ST_ACCEPT/SSL_CB_READ/SSL_CB_WRITE/SSL_CB_HANDSHAKE_START/SSL_CB_HANDSHAKE_DONE/...
    trace_event_tls_protection,             //
    trace_event_tls_record,                 //
    trace_event_tls_handshake,              //
    trace_event_tls_extension,              //
    trace_event_quic_packet,                //
    trace_event_quic_frame,                 //
    trace_event_http3,                      //
    trace_event_hpack,                      //
    trace_event_qpack,                      //
};

enum trace_option_t : uint32 {
    trace_bt = 1,      // backtrace
    trace_except = 2,  // exception
    trace_debug = 3,   // trace/debug
};

/**
 * @brief trace
 * @param uint32 option [in] see trace_option_t
 */
uint32 set_trace_option(uint32 option);
uint32 get_trace_option();

/**
 * @brief backtrace
 */
return_t trace_backtrace(return_t errorcode);

/**
 * @brief exception
 */
void set_trace_exception();
void reset_trace_exception();

}  // namespace hotplace

#endif
