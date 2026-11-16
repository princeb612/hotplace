/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   tls_protection_calc_psk.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/base/basic/dump_memory.hpp>
#include <hotplace/sdk/base/nostd/binary.hpp>
#include <hotplace/sdk/base/stream/basic_stream.hpp>
#include <hotplace/sdk/base/system/trace.hpp>
#include <hotplace/sdk/crypto/advisor/crypto_advisor.hpp>
#include <hotplace/sdk/crypto/basic/crypto_aead.hpp>
#include <hotplace/sdk/crypto/basic/crypto_hash.hpp>
#include <hotplace/sdk/crypto/basic/crypto_hmac.hpp>
#include <hotplace/sdk/crypto/basic/evp_pkey.hpp>
#include <hotplace/sdk/crypto/basic/openssl_ecdh.hpp>
#include <hotplace/sdk/crypto/basic/openssl_hash.hpp>
#include <hotplace/sdk/crypto/basic/openssl_kdf.hpp>
#include <hotplace/sdk/crypto/basic/transcript_hash.hpp>
#include <hotplace/sdk/net/tls/tls_advisor.hpp>
#include <hotplace/sdk/net/tls/tls_protection.hpp>
#include <hotplace/sdk/net/tls/tls_session.hpp>

namespace hotplace {
namespace net {

return_t tls_protection::calc_psk_binder(tls_session* session, const binary_t& binder_hash, binary_t& psk_binder) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == session) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        // RFC 8448 4.  Resumed 0-RTT Handshake

        auto tlsadvisor = tls_advisor::get_instance();
        auto advisor = crypto_advisor::get_instance();
        const tls_cipher_suite_t* hint_tls_alg = tlsadvisor->hintof_cipher_suite(get_cipher_suite());
        if (nullptr == hint_tls_alg) {
            ret = errorcode_t::not_supported;
            __leave2;
        }
        const hint_digest_t* hint_mac = advisor->hintof_digest(hint_tls_alg->mac);
        if (nullptr == hint_mac) {
            ret = errorcode_t::not_supported;
            __leave2;
        }

        openssl_kdf kdf;
        // RFC 8446 4.2.11.2: the binder hash is the hash associated with
        // the cipher suite used to establish this resumption PSK.
        binary_t context_resumption_binder_key;
        const binary_t& secret_resumption_early = get_secrets().get(tls_secret_t::resumption_early);
        if ((binder_hash.size() != hint_mac->digest_size) || (secret_resumption_early.size() != hint_mac->digest_size)) {
            ret = errorcode_t::bad_format;
            __leave2;
        }
        // The empty transcript hash is specific to the PSK's hash. Do not
        // reuse a cached value that may belong to another ticket's suite.
        binary_t context_empty_hash;
        openssl_digest digest;
        ret = digest.digest(hint_mac->fetchname, binary_t(), context_empty_hash);
        if (errorcode_t::success != ret) {
            __leave2;
        }
        ret = kdf.hkdf_expand_tls13_label(context_resumption_binder_key, hint_mac->fetchname, hint_mac->digest_size, secret_resumption_early, "res binder",
                                          context_empty_hash);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        // expanded
        binary_t context_resumption_finished_key;
        binary_t empty_ikm;
        ret = kdf.hkdf_expand_tls13_label(context_resumption_finished_key, hint_mac->fetchname, hint_mac->digest_size, context_resumption_binder_key, "finished",
                                          empty_ikm);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        // finished
        binary_t context_resumption_finished;
        openssl_mac mac;
        ret = mac.hmac(hint_tls_alg->mac, context_resumption_finished_key, binder_hash, context_resumption_finished);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        psk_binder = context_resumption_finished;

        // move
        get_secrets().assign(tls_secret_t::resumption_binder_hash, binder_hash);  // debug
        get_secrets().assign(tls_secret_t::resumption_binder_key, std::move(context_resumption_binder_key));
        get_secrets().assign(tls_secret_t::resumption_finished_key, std::move(context_resumption_finished_key));
        get_secrets().assign(tls_secret_t::resumption_finished, std::move(context_resumption_finished));
    }
    __finally2 {}

    return ret;
}

return_t tls_protection::calc_psk(tls_session* session, const binary_t& binder_hash, const binary_t& psk_binder) {
    binary_t expected_binder;
    return_t ret = calc_psk_binder(session, binder_hash, expected_binder);
    if (errorcode_t::success == ret) {
        // The binder authenticates the ClientHello transcript. Compare equal-length
        // values in constant time so the first differing byte is not observable.
        if ((expected_binder.size() != psk_binder.size()) || (0 != CRYPTO_memcmp(expected_binder.data(), psk_binder.data(), expected_binder.size()))) {
            ret = errorcode_t::mismatch;
        }
    }
    return ret;
}

return_t tls_protection::calc_resumption_ticket_psk(const binary_t& ticket_nonce, binary_t& ticket_psk) {
    return_t ret = errorcode_t::success;
    __try2 {
        const binary_t& secret_resumption_master = get_secrets().get(tls_secret_t::res_master);
        if (secret_resumption_master.empty()) {
            ret = errorcode_t::not_found;
            __leave2;
        }
        auto tlsadvisor = tls_advisor::get_instance();
        auto advisor = crypto_advisor::get_instance();
        const tls_cipher_suite_t* hint_tls_alg = tlsadvisor->hintof_cipher_suite(get_cipher_suite());
        if (nullptr == hint_tls_alg) {
            ret = errorcode_t::not_supported;
            __leave2;
        }
        const hint_digest_t* hint_mac = advisor->hintof_digest(hint_tls_alg->mac);
        if (nullptr == hint_mac) {
            ret = errorcode_t::not_supported;
            __leave2;
        }

        // RFC 8446 4.6.1: the ticket PSK is the HKDF-Expand-Label output.
        openssl_kdf kdf;
        ret = kdf.hkdf_expand_tls13_label(ticket_psk, hint_mac->fetchname, hint_mac->digest_size, secret_resumption_master, "resumption", ticket_nonce);
    }
    __finally2 {}
    return ret;
}

return_t tls_protection::calc_resumption_early_secret(const binary_t& psk, binary_t& early_secret) {
    auto tlsadvisor = tls_advisor::get_instance();
    auto advisor = crypto_advisor::get_instance();
    const tls_cipher_suite_t* hint_tls_alg = tlsadvisor->hintof_cipher_suite(get_cipher_suite());
    if (nullptr == hint_tls_alg) {
        return errorcode_t::not_supported;
    }
    const hint_digest_t* hint_mac = advisor->hintof_digest(hint_tls_alg->mac);
    if (nullptr == hint_mac) {
        return errorcode_t::not_supported;
    }
    binary_t zero_salt(hint_mac->digest_size, 0);
    openssl_kdf kdf;
    return kdf.hmac_kdf_extract(early_secret, hint_mac->fetchname, zero_salt, psk);
}

return_t tls_protection::calc_resumption_psk(const binary_t& ticket_nonce) {
    binary_t early_secret;
    return_t ret = calc_resumption_psk(ticket_nonce, early_secret);
    if (errorcode_t::success == ret) {
        get_secrets().assign(tls_secret_t::resumption_early, std::move(early_secret));
    }
    return ret;
}

return_t tls_protection::calc_resumption_psk(const binary_t& ticket_nonce, binary_t& resumption_psk) {
    binary_t ticket_psk;
    return_t ret = calc_resumption_ticket_psk(ticket_nonce, ticket_psk);
    if (errorcode_t::success == ret) {
        ret = calc_resumption_early_secret(ticket_psk, resumption_psk);
    }
    return ret;
}

}  // namespace net
}  // namespace hotplace
