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
#include <sdk/net/tls/sslkeylog_exporter.hpp>
#include <sdk/net/tls/tls_session.hpp>
#include <sdk/net/tls/types.hpp>

namespace hotplace {
namespace net {

sslkeylog_exporter* sslkeylog_exporter::get_instance() { return &_instance; }

sslkeylog_exporter sslkeylog_exporter::_instance;

sslkeylog_exporter::sslkeylog_exporter() {}

sslkeylog_exporter& sslkeylog_exporter::set(std::function<void(const char*)> func) {
    _keylog_hook = func;
    return *this;
}

void sslkeylog_exporter::log(const char* line) {
    if (_keylog_hook && line) {
        _keylog_hook(line);
    }
}

return_t sslkeylog_exporter::log(tls_session* session, tls_secret_t secret) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == session) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        if (nullptr == _keylog_hook) {
            __leave2;
        }

        auto& protection = session->get_tls_protection();
        auto& secrets = protection.get_secrets();

        auto lambda = [&](const char* name, const binary_t& client_random, const binary_t& value) -> void {
            basic_stream bs;
            bs << name << " " << base16_encode(client_random) << " " << base16_encode(value);
            _keylog_hook(bs);
        };
        switch (secret) {
            case tls_secret_c_ap_traffic: {
                lambda("CLIENT_TRAFFIC_SECRET_0", secrets.get(tls_context_client_hello_random), secrets.get(secret));
            } break;
            case tls_secret_s_ap_traffic: {
                lambda("SERVER_TRAFFIC_SECRET_0", secrets.get(tls_context_client_hello_random), secrets.get(secret));
            } break;
            case tls_secret_exp_master: {
                lambda("EXPORTER_SECRET", secrets.get(tls_context_client_hello_random), secrets.get(secret));
            } break;
            case tls_secret_c_hs_traffic: {
                lambda("CLIENT_HANDSHAKE_TRAFFIC_SECRET", secrets.get(tls_context_client_hello_random), secrets.get(secret));
            } break;
            case tls_secret_s_hs_traffic: {
                lambda("SERVER_HANDSHAKE_TRAFFIC_SECRET", secrets.get(tls_context_client_hello_random), secrets.get(secret));
            } break;
            case tls_secret_master: {
                lambda("CLIENT_RANDOM", secrets.get(tls_context_client_hello_random), secrets.get(secret));
            } break;
            default:
                break;
        }
    }
    __finally2 {}
    return ret;
}

}  // namespace net
}  // namespace hotplace
