/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/base/basic/dump_memory.hpp>
#include <sdk/base/stream/basic_stream.hpp>
#include <sdk/base/string/string.hpp>
#include <sdk/base/unittest/trace.hpp>
#include <sdk/net/tls/sslkeylog_importer.hpp>
#include <sdk/net/tls/tls_session.hpp>
#include <sdk/net/tls/types.hpp>

namespace hotplace {
namespace net {

sslkeylog_importer sslkeylog_importer::_instance;

sslkeylog_importer* sslkeylog_importer::get_instance() {
    _instance.load();
    return &_instance;
}

sslkeylog_importer::sslkeylog_importer() {}

void sslkeylog_importer::load() {
    if (_table.empty()) {
        critical_section_guard guard(_lock);
        if (_table.empty()) {
            struct sslkeylog_item {
                const char* name;
                tls_secret_t secret;
            };
            const sslkeylog_item resources[] = {
                // TLS 1.3
                {"SERVER_HANDSHAKE_TRAFFIC_SECRET", server_handshake_traffic_secret},
                {"CLIENT_HANDSHAKE_TRAFFIC_SECRET", client_handshake_traffic_secret},
                {"EXPORTER_SECRET", tls_secret_exp_master},
                {"SERVER_TRAFFIC_SECRET_0", server_application_traffic_secret_0},
                {"CLIENT_TRAFFIC_SECRET_0", client_application_traffic_secret_0},
                // TLS 1.2
                {"CLIENT_RANDOM", tls_secret_master},
            };
            for (auto i = 0; i < RTL_NUMBER_OF(resources); i++) {
                const sslkeylog_item* item = resources + i;
                _table.insert({item->name, item->secret});
                _rtable.insert({item->secret, item->name});
            }
        }
    }
}

sslkeylog_importer& sslkeylog_importer::operator<<(const std::string& secret) {
    add(secret);
    return *this;
}

return_t sslkeylog_importer::add(const std::string& secret) {
    return_t ret = errorcode_t::success;
    split_context_t* handle = nullptr;
    size_t count = 0;
    __try2 {
        ret = split_begin(&handle, secret.c_str(), " ");
        if (errorcode_t::success != ret) {
            __leave2;
        }

        split_count(handle, count);
        if (3 != count) {
            ret = errorcode_t::bad_format;
            __leave2;
        }

        std::string column0;
        std::string column1;
        std::string column2;
        split_get(handle, 0, column0);
        split_get(handle, 1, column1);
        split_get(handle, 2, column2);

        tls_secret_t secret;
        auto iter = _table.find(column0);
        if (_table.end() == iter) {
            ret = errorcode_t::bad_format;
            __leave2;
        }

        secret = iter->second;
        binary_t random;
        base16_decode(column1, random);
        binary_t value;
        base16_decode(column2, value);

        auto& secret_map = _keylogs[random];
        secret_map.insert({secret, value});
    }
    __finally2 { split_end(handle); }
    return ret;
}

void sslkeylog_importer::session_status_changed(tls_session* session, uint32 status) {
    if (session_status_client_hello == status) {
        auto& protection = session->get_tls_protection();
        const binary_t& client_random = protection.get_item(tls_context_client_hello_random);
        auto instance = sslkeylog_importer::get_instance();
        auto& secret_map = instance->_keylogs[client_random];
#if defined DEBUG
        auto client_random_b16 = base16_encode(client_random);
#endif
        for (const auto& item : secret_map) {
            auto secret = item.first;
            const binary_t& value = item.second;
            protection.set_item(secret, value);

#if defined DEBUG
            tls_advisor* tlsadvisor = tls_advisor::get_instance();
            if (istraceable()) {
                basic_stream dbs;
                auto& name = _instance._rtable[secret];
                dbs.println("%s %s %s", name.c_str(), client_random_b16.c_str(), base16_encode(value).c_str());
                trace_debug_event(trace_category_net, trace_event_tls_protection, &dbs);
            }
#endif
        }
    }
}

return_t sslkeylog_importer::attach(tls_session* session) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == session) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        session->get_tls_protection().use_pre_master_secret(true);
        session->set_hook_change_session_status(session_status_changed);
    }
    __finally2 {}
    return ret;
}

void sslkeylog_importer::clear() { _keylogs.clear(); }

}  // namespace net
}  // namespace hotplace
