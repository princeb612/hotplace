/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/base/basic/binary.hpp>
#include <sdk/base/unittest/trace.hpp>
#include <sdk/crypto/basic/crypto_advisor.hpp>
#include <sdk/crypto/basic/crypto_hash.hpp>
#include <sdk/crypto/basic/evp_key.hpp>
#include <sdk/crypto/basic/openssl_hash.hpp>
#include <sdk/crypto/basic/transcript_hash.hpp>
#include <sdk/net/tls/tls_advisor.hpp>
#include <sdk/net/tls/tls_protection.hpp>
#include <sdk/net/tls/tls_session.hpp>
// debug
#include <sdk/base/basic/dump_memory.hpp>
#include <sdk/base/stream/basic_stream.hpp>

namespace hotplace {
namespace net {

transcript_hash *tls_protection::get_transcript_hash() {
    critical_section_guard guard(_lock);
    if (nullptr == _transcript_hash) {
        if (get_cipher_suite()) {
            tls_advisor *tlsadvisor = tls_advisor::get_instance();
            auto cipher_suite = get_cipher_suite();
            const tls_cipher_suite_t *hint_tls_alg = tlsadvisor->hintof_cipher_suite(cipher_suite);
            auto hashalg = algof_mac(hint_tls_alg);
            transcript_hash_builder builder;
            _transcript_hash = builder.set(hashalg).build();

#if defined DEBUG
            if (istraceable()) {
                constexpr char constexpr_transcript_hash[] = "starting transcript_hash";
                constexpr char constexpr_cipher_suite[] = "cipher suite";
                crypto_advisor *advisor = crypto_advisor::get_instance();
                tls_advisor *tlsadvisor = tls_advisor::get_instance();
                auto mdname = advisor->nameof_md(hashalg);
                basic_stream dbs;
                dbs.println("# %s", constexpr_transcript_hash);
                dbs.println(" > %s 0x%04x %s", constexpr_cipher_suite, cipher_suite, tlsadvisor->cipher_suite_string(cipher_suite).c_str());
                dbs.println(" > %s", mdname);
                trace_debug_event(trace_category_net, trace_event_tls_protection, &dbs);
            }
#endif
        }
    }
    if (_transcript_hash) {
        _transcript_hash->addref();
    }
    return _transcript_hash;
}

return_t tls_protection::update_transcript_hash(tls_session *session, const byte_t *stream, size_t size) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == session) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        if (nullptr == stream) {
            __leave2;
        }

        // The hash does not include DTLS-only bytes in the records.
        // --> The hash does not include handshake reconstruction data bytes in the
        // records.

        auto hash = get_transcript_hash();
        if (hash) {
            if (is_kindof_dtls()) {
                basic_stream bs;
                // DTLS
                size_t offset_version = 12;
                size_t sizeof_reconstruction_data = 8;
                //  0.. 3 handshake header
                hash->update(stream, sizeof(tls_handshake_t));
                //  4..11 handshake reconstruction data (8 bytes)
                //
                // 12.. $ handshake, extension
                hash->update(stream + offset_version, size - offset_version);
            } else {
                // TLS
                // hash->digest(stream, size, digest);
                hash->update(stream, size);
            }

            hash->release();
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_protection::calc_transcript_hash(tls_session *session, const byte_t *stream, size_t size, binary_t &digest) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == session || (size && (nullptr == stream))) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        update_transcript_hash(session, stream, size);

        // The hash does not include DTLS-only bytes in the records.
        // --> The hash does not include handshake reconstruction data bytes in the
        // records.

        auto hash = get_transcript_hash();
        if (hash) {
            hash->digest(digest);
            hash->release();
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
};

return_t tls_protection::reset_transcript_hash(tls_session *session) {
    return_t ret = errorcode_t::success;
    auto hash = get_transcript_hash();
    if (hash) {
        hash->reset();
        hash->release();
    }
    return ret;
}

return_t tls_protection::calc_context_hash(tls_session *session, hash_algorithm_t alg, const byte_t *stream, size_t size, binary_t &digest) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == session || (size && (nullptr == stream))) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        // The hash does not include DTLS-only bytes in the records.
        // --> The hash does not include handshake reconstruction data bytes in the
        // records.

        transcript_hash_builder builder;
        auto hash = builder.set(alg).build();
        if (hash) {
            if (is_kindof_dtls()) {
                basic_stream bs;
                // DTLS
                size_t offset_version = 12;
                size_t sizeof_reconstruction_data = 8;
                //  0.. 3 handshake header
                hash->update(stream, sizeof(tls_handshake_t));
                //  4..11 handshake reconstruction data (8 bytes)
                //
                // 12.. $ handshake, extension
                hash->update(stream + offset_version, size - offset_version);
                hash->digest(digest);
            } else {
                // TLS
                // hash->digest(stream, size, digest);
                hash->update(stream, size);
                hash->digest(digest);
            }

            hash->release();
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

}  // namespace net
}  // namespace hotplace
