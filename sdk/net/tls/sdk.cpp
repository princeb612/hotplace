/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc https://www.iana.org/assignments/aead-parameters/aead-parameters.xhtml
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/crypto/basic/crypto_key.hpp>
#include <sdk/crypto/basic/crypto_keychain.hpp>
#include <sdk/net/tls/sdk.hpp>
#include <sdk/net/tls/sslkeylog_exporter.hpp>
#include <sdk/net/tls/tls_advisor.hpp>
#include <sdk/net/tls/tls_protection.hpp>  // KID

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

}  // namespace net
}  // namespace hotplace
