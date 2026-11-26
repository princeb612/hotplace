/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   tls_protection_hash.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/base/nostd/binary.hpp>
#include <hotplace/sdk/base/system/trace.hpp>
#include <hotplace/sdk/crypto/advisor/crypto_advisor.hpp>
#include <hotplace/sdk/crypto/basic/crypto_hash.hpp>
#include <hotplace/sdk/crypto/basic/evp_pkey.hpp>
#include <hotplace/sdk/crypto/basic/openssl_hash.hpp>
#include <hotplace/sdk/crypto/basic/transcript_hash.hpp>
#include <hotplace/sdk/net/tls/tls_advisor.hpp>
#include <hotplace/sdk/net/tls/tls_protection.hpp>
#include <hotplace/sdk/net/tls/tls_session.hpp>
// debug
#include <hotplace/sdk/base/basic/dump_memory.hpp>
#include <hotplace/sdk/base/stream/basic_stream.hpp>

namespace hotplace {
namespace net {

transcript_hash* tls_protection::get_transcript_hash() {
    critical_section_guard guard(_lock);
    if (nullptr == _transcript_hash) {
        if (get_cipher_suite()) {
            tls_advisor* tlsadvisor = tls_advisor::get_instance();
            auto cipher_suite = get_cipher_suite();
            const tls_cipher_suite_t* hint_tls_alg = tlsadvisor->hintof_cipher_suite(cipher_suite);
            auto hashalg = algof_mac(hint_tls_alg);
            transcript_hash_builder builder;
            _transcript_hash = builder.set(hashalg).build();

#if defined DEBUG
            if (istraceable(trace_category_t::trace_category_net)) {
                trace_debug_event(trace_category_t::trace_category_net, trace_event_t::trace_event_tls_protection, [&](basic_stream& dbs) -> void {
                    constexpr char constexpr_transcript_hash[] = ANSI_ESCAPE "1;33mstarting transcript_hash" ANSI_ESCAPE "0m";
                    constexpr char constexpr_cipher_suite[] = "cipher suite";
                    crypto_advisor* advisor = crypto_advisor::get_instance();
                    tls_advisor* tlsadvisor = tls_advisor::get_instance();
                    auto mdname = advisor->nameof_md(hashalg);
                    dbs.println("# %s", constexpr_transcript_hash);
                    dbs.println(" > %s 0x%04x %s", constexpr_cipher_suite, cipher_suite, tlsadvisor->nameof_tls_cipher_suite(cipher_suite).c_str());
                    dbs.println(" > %s", mdname);
                });
            }
#endif
        }
    }
    if (_transcript_hash) {
        _transcript_hash->addref();
    }
    return _transcript_hash;
}

return_t tls_protection::update_transcript_hash(tls_session* session, const byte_t* stream, size_t size) {
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
        if (nullptr == hash) {
            ret = errorcode_t::not_supported;
            __leave2_trace(ret);
        }
        if (hash) {
            if (is_kindof_dtls() && is_kindof_tls1_3()) {
                // RFC 9147 5.2.  DTLS Handshake Message Format
                // In DTLS 1.3, the message transcript is computed over the original TLS 1.3-style Handshake messages
                // without the message_seq, fragment_offset, and fragment_length values.

                basic_stream bs;
                size_t offset_body = sizeof(dtls_handshake_t);
                //  0.. 3 handshake header
                ret = hash->update(stream, sizeof(tls_handshake_t));
                if (errorcode_t::success != ret) {
                    hash->release();
                    __leave2_trace(ret);
                }
                //  4..11 handshake reconstruction data (8 bytes)
                //
                // 12.. $ handshake, extension
                ret = hash->update(stream + offset_body, size - offset_body);
                if (errorcode_t::success != ret) {
                    hash->release();
                    __leave2_trace(ret);
                }
#if defined DEBUG
                if (istraceable(trace_category_t::trace_category_net, loglevel_t::loglevel_debug)) {
                    trace_debug_event(trace_category_t::trace_category_net, trace_event_t::trace_event_tls_protection, [&](basic_stream& dbs) -> void {
                        binary_t digest;
                        hash->digest(digest);
                        dbs.printf(ANSI_ESCAPE "1;34m");
                        dbs.println("> update transcript hash @0x%p", this);
                        dump_memory(stream, sizeof(tls_handshake_t), &dbs, 16, 3, 0, dump_notrunc);
                        dbs.println("> update transcript hash @0x@%p", this);
                        dump_memory(stream + offset_body, size - offset_body, &dbs, 16, 3, 0, dump_notrunc);
                        dbs.printf(ANSI_ESCAPE "1;33m");
                        dbs.println("   %s", base16_encode(digest).c_str());
                        dbs.printf(ANSI_ESCAPE "0m");
                    });
                }
#endif
            } else {
                // RFC 6347 4.2.6.  CertificateVerify and Finished Messages
                // Hash calculations include entire handshake messages, including DTLS-specific fields: message_seq, fragment_offset, and fragment_length.
                // the initial ClientHello and HelloVerifyRequest MUST NOT be included in the CertificateVerify or Finished MAC computations.

                ret = hash->update(stream, size);
                if (errorcode_t::success != ret) {
                    hash->release();
                    __leave2_trace(ret);
                }
#if defined DEBUG
                if (istraceable(trace_category_t::trace_category_net, loglevel_t::loglevel_debug)) {
                    trace_debug_event(trace_category_t::trace_category_net, trace_event_t::trace_event_tls_protection, [&](basic_stream& dbs) -> void {
                        binary_t digest;
                        hash->digest(digest);
                        dbs.printf(ANSI_ESCAPE "1;34m");
                        dbs.println("> update transcript hash @0x%p size 0x%zx", this, size);
                        // dump_memory(stream, size, &dbs, 16, 3, 0, dump_notrunc);
                        size_t hdrsize = 0;
                        if (is_kindof_dtls()) {
                            hdrsize = sizeof(dtls_handshake_t);
                        } else {
                            hdrsize = sizeof(tls_handshake_t);
                        }
                        dump_memory(stream, hdrsize, &dbs, 16, 3, 0, dump_notrunc);
                        dump_memory(stream + hdrsize, size - hdrsize, &dbs, 16, 3, 0, dump_notrunc);
                        dbs.printf(ANSI_ESCAPE "1;33m");
                        dbs.println("   %s", base16_encode(digest).c_str());
                        dbs.printf(ANSI_ESCAPE "0m");
                    });
                }
#endif
            }

            hash->release();
        }
    }
    __finally2 {}
    return ret;
}

return_t tls_protection::calc_transcript_hash(tls_session* session, const byte_t* stream, size_t size, binary_t& digest) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == session || (size && (nullptr == stream))) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        ret = update_transcript_hash(session, stream, size);
        if (errorcode_t::success != ret) {
            __leave2_trace(ret);
        }

        // The hash does not include DTLS-only bytes in the records.
        // --> The hash does not include handshake reconstruction data bytes in the
        // records.

        auto hash = get_transcript_hash();
        if (nullptr == hash) {
            ret = errorcode_t::not_supported;
            __leave2_trace(ret);
        }
        if (hash) {
            ret = hash->digest(digest);
            hash->release();
            if (errorcode_t::success != ret) {
                __leave2_trace(ret);
            }
        }
    }
    __finally2 {}
    return ret;
};

return_t tls_protection::reset_transcript_hash(tls_session* session) {
    return_t ret = errorcode_t::success;
    auto hash = get_transcript_hash();
    if (hash) {
        hash->reset();
        hash->release();
    }
    return ret;
}

return_t tls_protection::calc_context_hash(tls_session* session, hash_algorithm_t alg, const byte_t* stream, size_t size, binary_t& digest) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == session || (size && (nullptr == stream))) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        // The hash does not include DTLS-only bytes in the records.
        // --> The hash does not include handshake reconstruction data bytes in the
        // records.

        // RFC 8446 4.2.11.2 / RFC 9846: the ClientHello2 binder transcript
        // includes message_hash(ClientHello1), HelloRetryRequest, and the
        // truncated ClientHello2, using the PSK-associated hash for the outer digest.
        transcript_hash* hash = nullptr;
        if (tls_flow_t::hello_retry_request == get_flow()) {
            // The live handshake transcript is maintained with the HRR-selected
            // cipher-suite hash. RFC 9846 requires the binder's outer transcript
            // hash to use the PSK-associated hash instead; only the synthetic
            // message_hash payload itself uses the HRR-selected hash.
            const binary_t& binder_transcript_prefix = get_secrets().get(tls_secret_t::hello_retry_request_transcript_prefix);
            if (binder_transcript_prefix.empty()) {
                ret = errorcode_t::not_found;
                __leave2;
            }
            transcript_hash_builder builder;
            hash = builder.set(alg).build();
            if (hash) {
                hash->update(binder_transcript_prefix.data(), binder_transcript_prefix.size());
            }
        } else {
            transcript_hash_builder builder;
            hash = builder.set(alg).build();
        }
        if (nullptr == hash) {
            ret = errorcode_t::not_supported;
            __leave2;
        }
        if (hash) {
            if (is_kindof_dtls()) {
                // DTLS 1.3 transcript excludes the 8-byte handshake
                // reconstruction fields, but includes the handshake header.
                constexpr size_t offset_reconstruction = 12;
                hash->update(stream, sizeof(tls_handshake_t));
                if (size > offset_reconstruction) {
                    hash->update(stream + offset_reconstruction, size - offset_reconstruction);
                }
            } else {
                hash->update(stream, size);
            }
            hash->digest(digest);
            hash->release();
        }
    }
    __finally2 {}
    return ret;
}

}  // namespace net
}  // namespace hotplace
