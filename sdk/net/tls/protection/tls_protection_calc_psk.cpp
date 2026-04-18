/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/base/basic/binary.hpp>
#include <hotplace/sdk/base/basic/dump_memory.hpp>
#include <hotplace/sdk/base/stream/basic_stream.hpp>
#include <hotplace/sdk/base/unittest/trace.hpp>
#include <hotplace/sdk/crypto/basic/crypto_advisor.hpp>
#include <hotplace/sdk/crypto/basic/crypto_aead.hpp>
#include <hotplace/sdk/crypto/basic/crypto_hash.hpp>
#include <hotplace/sdk/crypto/basic/crypto_hmac.hpp>
#include <hotplace/sdk/crypto/basic/evp_pkey.hpp>
#include <hotplace/sdk/crypto/basic/openssl_ecdh.hpp>
#include <hotplace/sdk/crypto/basic/openssl_hash.hpp>
#include <hotplace/sdk/crypto/basic/openssl_kdf.hpp>
#include <hotplace/sdk/crypto/basic/transcript_hash.hpp>
#include <hotplace/sdk/net/tls/sslkeylog_exporter.hpp>
#include <hotplace/sdk/net/tls/tls_advisor.hpp>
#include <hotplace/sdk/net/tls/tls_protection.hpp>
#include <hotplace/sdk/net/tls/tls_session.hpp>

namespace hotplace {
namespace net {

return_t tls_protection::calc_psk(tls_session *session, const binary_t &binder_hash, const binary_t &psk_binder) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == session) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        get_secrets().assign(tls_context_resumption_binder_hash, binder_hash);  // debug

        // RFC 8448 4.  Resumed 0-RTT Handshake

        openssl_kdf kdf;
        // PRK
        binary_t context_resumption_binder_key;
        const binary_t &secret_resumption_early = get_secrets().get(tls_secret_resumption_early);
        const binary_t &context_empty_hash = get_secrets().get(tls_context_empty_hash);
        kdf.hkdf_expand_tls13_label(context_resumption_binder_key, sha2_256, 32, secret_resumption_early, "res binder", context_empty_hash);
        get_secrets().assign(tls_context_resumption_binder_key, context_resumption_binder_key);

        // expanded
        binary_t context_resumption_finished_key;
        binary_t empty_ikm;
        kdf.hkdf_expand_tls13_label(context_resumption_finished_key, sha2_256, 32, context_resumption_binder_key, "finished", empty_ikm);
        get_secrets().assign(tls_context_resumption_finished_key, context_resumption_finished_key);

        // finished
        binary_t context_resumption_finished;
        openssl_mac mac;
        mac.hmac(sha2_256, context_resumption_finished_key, binder_hash, context_resumption_finished);
        get_secrets().assign(tls_context_resumption_finished, context_resumption_finished);

        if (psk_binder != context_resumption_finished) {
            ret = errorcode_t::mismatch;
        }
    }
    __finally2 {}

    return ret;
}

}  // namespace net
}  // namespace hotplace
