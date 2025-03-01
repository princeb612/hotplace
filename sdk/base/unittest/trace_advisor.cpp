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
                _resource_map.insert({category_debug_internal, e});
            }
            {
                events e;
                e.cname = "crypto";
                e.event_map.insert({crypto_event_openssl_info, "openssl info"});
                e.event_map.insert({crypto_event_openssl_nosupport, "no support"});
                e.event_map.insert({crypto_event_openssl_tls_state, "state"});
                e.event_map.insert({crypto_event_jose, "JOSE"});
                e.event_map.insert({crypto_event_cose, "COSE"});
                _resource_map.insert({category_crypto, e});
            }
            {
                events e;
                e.cname = "network";
                e.event_map.insert({net_event_netsession_produce, "produce network session"});
                e.event_map.insert({net_event_netsession_consume_http2, "consume network session"});
                e.event_map.insert({net_event_httpserver_consume, "consume http_server"});
                e.event_map.insert({net_event_httpresponse, "http_response"});
                e.event_map.insert({net_event_header_compression_insert, "header compression insert"});
                e.event_map.insert({net_event_header_compression_evict, "header compression evict"});
                e.event_map.insert({net_event_header_compression_select, "header compression select"});
                e.event_map.insert({net_event_http2_push_promise, "push promise"});
                e.event_map.insert({net_event_tls_read, "TLS read"});
                e.event_map.insert({net_event_tls_write, "TLS write"});
                e.event_map.insert({net_event_tls_dump, "TLS dump"});
                e.event_map.insert({net_event_quic_read, "QUIC read"});
                e.event_map.insert({net_event_quic_write, "QUIC write"});
                e.event_map.insert({net_event_quic_dump, "QUIC dump"});
                _resource_map.insert({category_net, e});
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
