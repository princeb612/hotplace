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
                e.cname = "openssl";
                e.event_map.insert({crypto_event_info_openssl, "info"});
                e.event_map.insert({crypto_event_openssl_nosupport, "no support"});
                e.event_map.insert({crypto_event_state_ossl_tls, "state"});
                _resource_map.insert({category_crypto, e});
            }
            {
                events e;
                e.cname = "network_session";
                e.event_map.insert({net_session_event_produce, "produce"});
                e.event_map.insert({net_session_event_http2_consume, "consume"});
                _resource_map.insert({category_net_session, e});
            }
            {
                events e;
                e.cname = "http_server";
                e.event_map.insert({http_server_event_consume, "consume"});
                _resource_map.insert({category_http_server, e});
            }
            {
                events e;
                e.cname = "http_request";
                _resource_map.insert({category_http_request, e});
            }
            {
                events e;
                e.cname = "http_response";
                e.event_map.insert({http_response_event_getresponse, "response"});
                _resource_map.insert({category_http_response, e});
            }
            {
                events e;
                e.cname = "header compression";
                e.event_map.insert({header_compression_event_insert, "insert"});
                e.event_map.insert({header_compression_event_evict, "evict"});
                e.event_map.insert({header_compression_event_select, "select"});
                _resource_map.insert({category_header_compression, e});
            }
            {
                events e;
                e.cname = "serverpush";
                e.event_map.insert({http2_push_event_push_promise, "push promise"});
                _resource_map.insert({category_header_compression, e});
            }
            {
                events e;
                e.cname = "TLS";
                e.event_map.insert({tls_event_read, "read"});
                e.event_map.insert({tls_event_write, "write"});
                _resource_map.insert({category_tls1, e});
            }
            {
                events e;
                e.cname = "QUIC";
                e.event_map.insert({quic_event_read, "read"});
                e.event_map.insert({quic_event_write, "write"});
                _resource_map.insert({category_quic, e});
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
