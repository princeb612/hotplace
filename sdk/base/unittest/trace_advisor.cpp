/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/base/unittest/trace.hpp>

namespace hotplace {

trace_advisor trace_advisor::_instance;

trace_advisor* trace_advisor::get_instance() {
    _instance.load();
    return &_instance;
}

trace_advisor::trace_advisor() {}

void trace_advisor::load() {
    if (_resource_map.empty()) {
        critical_section_guard guard(_lock);
        if (_resource_map.empty()) {
            {
                events e;
                e.cname = "internal";
                e.event_map.insert({trace_event_internal, ""});
                e.event_map.insert({trace_event_backtrace, "backtrace"});
                e.event_map.insert({trace_event_multiplexer, "multiplexer"});
                e.event_map.insert({trace_event_socket, "socket"});
                _resource_map.insert({trace_category_internal, e});
            }
            {
                events e;
                e.cname = "crypto";
                e.event_map.insert({trace_event_openssl_info, "openssl info"});
                e.event_map.insert({trace_event_openssl_nosupport, "no support"});
                e.event_map.insert({trace_event_encryption, "encryption"});
                e.event_map.insert({trace_event_decryption, "decryption"});
                e.event_map.insert({trace_event_digest, "digest"});
                e.event_map.insert({trace_event_mac, "mac"});
                e.event_map.insert({trace_event_jose_encryption, "JOSE encryption"});
                e.event_map.insert({trace_event_jose_signing, "JOSE signing"});
                e.event_map.insert({trace_event_cose_keydistribution, "COSE keydistribution"});
                e.event_map.insert({trace_event_cose_encryption, "COSE encryption"});
                e.event_map.insert({trace_event_cose_signing, "COSE signing"});
                e.event_map.insert({trace_event_cose_mac, "COSE mac"});
                _resource_map.insert({trace_category_crypto, e});
            }
            {
                events e;
                e.cname = "network";
                e.event_map.insert({trace_event_net_produce, "produce"});
                e.event_map.insert({trace_event_net_consume, "consume"});
                e.event_map.insert({trace_event_net_request, "request"});
                e.event_map.insert({trace_event_net_response, "response"});
                e.event_map.insert({trace_event_header_compression_insert, "header compression insert"});
                e.event_map.insert({trace_event_header_compression_evict, "header compression evict"});
                e.event_map.insert({trace_event_header_compression_select, "header compression select"});
                e.event_map.insert({trace_event_http2_push_promise, "push promise"});
                e.event_map.insert({trace_event_openssl_tls_state, "TLS state"});
                e.event_map.insert({trace_event_tls_protection, "TLS protection"});
                e.event_map.insert({trace_event_tls_record, "TLS record"});
                e.event_map.insert({trace_event_tls_handshake, "TLS handshake"});
                e.event_map.insert({trace_event_tls_extension, "TLS extension"});
                e.event_map.insert({trace_event_quic_packet, "QUIC packet"});
                e.event_map.insert({trace_event_quic_frame, "QUIC frame"});
                e.event_map.insert({trace_event_http3, "HTTP/3"});
                _resource_map.insert({trace_category_net, e});
            }
        }
    }
}

std::string trace_advisor::nameof_category(trace_category_t category) {
    std::string res;
    critical_section_guard guard(_lock);
    auto iter = _resource_map.find(category);
    if (_resource_map.end() != iter) {
        res = iter->second.cname;
    }
    return res;
}

void trace_advisor::get_names(trace_category_t category, uint32 event, std::string& cvalue, std::string& evalue) {
    cvalue.clear();
    evalue.clear();

    critical_section_guard guard(_lock);
    auto citer = _resource_map.find(category);
    if (_resource_map.end() != citer) {
        cvalue = citer->second.cname;
        auto const& em = citer->second.event_map;
        auto eiter = em.find(event);
        if (em.end() != eiter) {
            evalue = eiter->second;
        }
    }
}

}  // namespace hotplace
