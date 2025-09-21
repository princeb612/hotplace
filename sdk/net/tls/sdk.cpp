/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc https://www.iana.org/assignments/aead-parameters/aead-parameters.xhtml
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/crypto/basic/crypto_key.hpp>
#include <hotplace/sdk/crypto/basic/crypto_keychain.hpp>
#include <hotplace/sdk/net/tls/quic/frame/quic_frame.hpp>
#include <hotplace/sdk/net/tls/sdk.hpp>
#include <hotplace/sdk/net/tls/sslkeylog_exporter.hpp>
#include <hotplace/sdk/net/tls/tls/handshake/tls_handshakes.hpp>
#include <hotplace/sdk/net/tls/tls_advisor.hpp>
#include <hotplace/sdk/net/tls/tls_protection.hpp>
#include <hotplace/sdk/net/tls/tls_session.hpp>

namespace hotplace {
namespace net {

return_t load_certificate(const char* certfile, const char* keyfile, const char* chainfile) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == certfile || nullptr == keyfile) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        crypto_key temp;
        crypto_keychain keychain;
        ret = keychain.load_file(&temp, key_certfile, certfile, keydesc(KID_TLS_SERVER_CERTIFICATE_PUBLIC));
        if (errorcode_t::success != ret) {
            __leave2;
        }
        ret = keychain.load_file(&temp, key_pemfile, keyfile, keydesc(KID_TLS_SERVER_CERTIFICATE_PRIVATE));
        if (errorcode_t::success != ret) {
            __leave2;
        }

        // copy pointers and increase reference counter
        tls_advisor* tlsadvisor = tls_advisor::get_instance();
        auto& keys = tlsadvisor->get_keys();
        auto lambda = [&](crypto_key_object* k, void*) -> void { keys.add(*k, true); };
        temp.for_each(lambda, nullptr);
    }
    __finally2 {}
    return ret;
}

void set_tls_keylog_callback(std::function<void(const char*)> func) {
    auto sslkeylog = sslkeylog_exporter::get_instance();
    sslkeylog->set(func);
}

bool is_anydirection(tls_direction_t dir) { return (dir == from_any); }

bool is_unidirection(tls_direction_t dir) { return (client_initiated_uni == dir) || (server_initiated_uni == dir); }

bool is_bidirection(tls_direction_t dir) { return (client_initiated_bidi == dir) || (server_initiated_bidi == dir); }

bool is_clientinitiated(tls_direction_t dir) { return (client_initiated_uni == dir) || (client_initiated_bidi == dir); }

bool is_serverinitiated(tls_direction_t dir) { return (server_initiated_uni == dir) || (server_initiated_bidi == dir); }

return_t kindof_handshake(tls_handshake* handshake, protection_space_t& space) {
    return_t ret = errorcode_t::success;
    __try2 {
        space = protection_default;

        if (nullptr == handshake) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        auto type = handshake->get_type();
        switch (type) {
            case tls_hs_client_hello:
            case tls_hs_server_hello: {
                space = protection_initial;
            } break;
            case tls_hs_encrypted_extensions:
            case tls_hs_certificate:
            case tls_hs_certificate_verify:
            case tls_hs_finished: {
                space = protection_handshake;
            } break;
            case tls_hs_new_session_ticket: {
                space = protection_application;
            } break;
            default: {
                ret = errorcode_t::not_supported;
            } break;
        }
    }
    __finally2 {}
    return ret;
}

bool is_kindof_handshake(tls_handshake* handshake, protection_space_t space) {
    bool ret = false;
    protection_space_t sp;
    if (success == kindof_handshake(handshake, sp)) {
        ret = (sp == space);
    }
    return ret;
}

return_t kindof_frame(quic_frame* frame, protection_space_t& space) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == frame) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        space = protection_application;
    }
    __finally2 {}
    return ret;
}

bool is_kindof_frame(quic_frame* frame, protection_space_t space) {
    bool ret = false;
    protection_space_t sp;
    if (success == kindof_frame(frame, sp)) {
        ret = (sp == space);
    }
    return ret;
}

return_t kindof_frame(quic_frame_t type, protection_space_t& space) {
    return_t ret = errorcode_t::success;
    space = protection_application;
    return success;
}

bool is_kindof_frame(quic_frame_t type, protection_space_t space) {
    bool ret = false;
    protection_space_t sp;
    if (success == kindof_frame(type, sp)) {
        ret = (sp == space);
    }
    return ret;
}

// bool is_kindof_h3(tls_session* session) {
bool is_kindof_alpn(tls_session* session, const std::string& alpn) {
    bool ret = false;
    if (session) {
        std::string session_alpn = bin2str(session->get_tls_protection().get_secrets().get(tls_context_alpn));
        ret = (alpn == session_alpn);
    }
    return ret;
}

}  // namespace net
}  // namespace hotplace
