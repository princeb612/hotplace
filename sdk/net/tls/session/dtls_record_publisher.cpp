/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   dtls_record_publisher.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/base/basic/dump_memory.hpp>
#include <hotplace/sdk/base/nostd/exception.hpp>
#include <hotplace/sdk/base/stream/basic_stream.hpp>
#include <hotplace/sdk/base/stream/splitter.hpp>
#include <hotplace/sdk/base/system/trace.hpp>
#include <hotplace/sdk/crypto/advisor/crypto_advisor.hpp>
#include <hotplace/sdk/io/basic/payload.hpp>
#include <hotplace/sdk/net/tls/dtls_record_publisher.hpp>
#include <hotplace/sdk/net/tls/tls/handshake/dtls_handshake_fragmented.hpp>
#include <hotplace/sdk/net/tls/tls/handshake/tls_handshake.hpp>
#include <hotplace/sdk/net/tls/tls/record/tls_record.hpp>
#include <hotplace/sdk/net/tls/tls/record/tls_record_builder.hpp>
#include <hotplace/sdk/net/tls/tls/record/tls_record_handshake.hpp>
#include <hotplace/sdk/net/tls/tls/record/tls_records.hpp>
#include <hotplace/sdk/net/tls/tls_advisor.hpp>
#include <hotplace/sdk/net/tls/tls_protection.hpp>
#include <hotplace/sdk/net/tls/tls_session.hpp>
#include <hotplace/sdk/net/tls/types.hpp>

namespace hotplace {
namespace net {

dtls_record_publisher::dtls_record_publisher() : _session(nullptr), _fragment_size(1024), _segment_size(1200), _pmtu_estimate(0), _flags(0) {}

void dtls_record_publisher::set_fragment_size(uint16 size) {
    const uint16 minsize = 1 << 7;
    const uint16 maxsize = 1 << 10;
    adjust_range(size, minsize, maxsize);
    _fragment_size = size;
}

uint16 dtls_record_publisher::get_fragment_size() const { return _fragment_size; }

void dtls_record_publisher::set_segment_size(uint16 size) { _segment_size = size; }

uint16 dtls_record_publisher::get_max_size() const { return _segment_size; }

void dtls_record_publisher::set_pmtu_estimate(size_t size) { _pmtu_estimate = size; }

size_t dtls_record_publisher::get_pmtu_estimate() const { return _pmtu_estimate; }

return_t dtls_record_publisher::get_record_expansion(tls_direction_t dir, size_t plaintext_size, size_t& expansion) const {
    return_t ret = errorcode_t::success;
    __try2 {
        expansion = 0;

        auto session = get_session();
        if ((nullptr == session) || (session_type_t::dtls != session->get_type())) {
            ret = errorcode_t::no_session;
            __leave2;
        }
        if (plaintext_size > 0xffff) {
            ret = errorcode_t::exceed;
            __leave2;
        }

        // DTLSPlaintext / legacy DTLS record header.
        expansion = sizeof(dtls_header);

        auto& protection = session->get_tls_protection();
        if (false == session->get_session_info(dir).apply_protection()) {
            // do nothing
            __leave2;
        }

        auto tagsize = protection.get_tag_size();
        if (0 == tagsize) {
            expansion = 0;
            ret = errorcode_t::not_supported;
            __leave2;
        }

        auto cs = protection.get_cipher_suite();
        auto tlsadvisor = tls_advisor::get_instance();
        auto hint_cipher = tlsadvisor->hintof_cipher(cs);
        if (nullptr == hint_cipher) {
            expansion = 0;
            ret = errorcode_t::not_supported;
            __leave2;
        }

        if (protection.is_kindof_tls13()) {
            auto mode = typeof_mode(hint_cipher);
            if ((crypt_mode_t::gcm != mode) && (crypt_mode_t::ccm != mode) && (crypt_mode_t::poly1305 != mode)) {
                expansion = 0;
                ret = errorcode_t::not_supported;
                __leave2;
            }

            // Unified header: first byte + conservative two-byte sequence + length.
            // Include the inner content type, authentication tag, and any padding
            // needed to make the ciphertext sample at least 16 bytes. CID is not
            // currently emitted by dtls13_ciphertext.
            size_t inner_plaintext_size = plaintext_size + 1;
            size_t sample_size = inner_plaintext_size + tagsize;
            size_t padding_size = (sample_size < 16) ? (16 - sample_size) : 0;
            expansion = 6 + tagsize + padding_size;
            __leave2;
        }

        if (tlsadvisor->is_kindof_cbc(cs)) {
            auto hint_blockcipher = tlsadvisor->hintof_blockcipher(cs);
            if (nullptr == hint_blockcipher) {
                expansion = 0;
                ret = errorcode_t::not_supported;
                __leave2;
            }

            size_t block_size = crypto::sizeof_block(hint_blockcipher);
            size_t iv_size = crypto::sizeof_iv(hint_blockcipher);
            if ((0 == block_size) || (0 == iv_size)) {
                expansion = 0;
                ret = errorcode_t::not_supported;
                __leave2;
            }

            bool etm = session->get_keyvalue().get(session_encrypt_then_mac);
            size_t encrypted_size = plaintext_size + 1 + (etm ? block_size : tagsize);
            size_t padding_size = block_size - (encrypted_size % block_size);

            // The CBC implementation adds one padding byte before OpenSSL's
            // PKCS#7 padding. MtE prepends an explicit IV; EtM encrypts an IV
            // block with the plaintext and appends the MAC.
            expansion += (etm ? block_size : iv_size) + tagsize + 1 + padding_size;
            __leave2;
        }

        auto mode = typeof_mode(hint_cipher);
        switch (mode) {
            case crypt_mode_t::gcm:
            case crypt_mode_t::ccm:
                // TLS 1.2 / DTLS 1.2 carries an eight-byte explicit nonce.
                expansion += 8 + tagsize;
                break;
            case crypt_mode_t::poly1305:
                expansion += tagsize;
                break;
            default:
                ret = errorcode_t::not_supported;
                break;
        }
    }
    __finally2 {
        if (errorcode_t::success != ret) {
            expansion = 0;
        }
    }
    return ret;
}

return_t dtls_record_publisher::publish(tls_record* record, tls_direction_t dir, std::list<binary_t>& container) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == record) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        __try2 {
            record->addref();

            tls_advisor* tlsadvisor = tls_advisor::get_instance();
            tls_record_builder builder;
            auto session = get_session();
            if (nullptr == session) {
                throw exception(errorcode_t::no_session);
            } else {
                if (session_type_t::dtls != session->get_type()) {
                    throw exception(errorcode_t::no_session);
                }
            }
            // auto session_type = session->get_type();
            size_t hdrsize = sizeof(dtls_handshake_t);

            struct spl_desc {
                tls_handshake_type_t hstype;
                uint16 hsseq;
            };

            splitter<spl_desc> spl;
            spl.set_segment_size(get_fragment_size());

            {
                auto rctype = record->get_type();
                auto& kv = session->get_session_info(dir).get_keyvalue();
                uint16 hsseq = t_narrow_cast(kv.get(session_dtls_message_seq));

                std::list<tls_record*> records;

                auto lambda_handshake = [&dir, &tlsadvisor, &spl, &hdrsize, &hsseq](tls_handshake* handshake) -> return_t {
                    return_t ret = errorcode_t::success;
                    binary_t bin;
                    __try2 {
                        // generate body + update transcript hash
                        ret = handshake->write(dir, bin);
                        if (errorcode_t::success != ret) {
                            __leave2;
                        }
                        // and now trim handshake header
                        bin.erase(bin.begin(), bin.begin() + hdrsize);

                        auto hstype = handshake->get_type();

                        spl_desc desc;
                        desc.hstype = hstype;
                        desc.hsseq = hsseq;

#if defined DEBUG
                        if (istraceable(trace_category_t::trace_category_net, loglevel_t::loglevel_debug)) {
                            trace_debug_event(trace_category_t::trace_category_net, trace_event_t::trace_event_tls_record, [&](basic_stream& dbs) -> void {
                                dbs.printf(ANSI_ESCAPE "1;36m");
                                dbs.println("# publish %s %i %s", tlsadvisor->nameof_tls_handshake(hstype).c_str(), hsseq, tlsadvisor->nameof_direction(dir, 1).c_str());
                                dbs.printf(ANSI_ESCAPE "0m");
                                dump_memory(bin, &dbs, 16, 3, 0, dump_notrunc);
                            });
                        }
#endif
                        spl.add(std::move(bin), std::move(desc));

                        ++hsseq;
                    }
                    __finally2 {}
                    return ret;
                };

                auto lambda_split = [this, &dir, &tlsadvisor, &builder, &records, &session, &rctype](uint32 flags, const byte_t* stream, size_t size, size_t fragoffset,
                                                                                                     size_t fragsize, const spl_desc& desc) -> void {
#if defined DEBUG
                    if (istraceable(trace_category_t::trace_category_net, loglevel_t::loglevel_debug)) {
                        trace_debug_event(trace_category_t::trace_category_net, trace_event_t::trace_event_tls_record, [&](basic_stream& dbs) -> void {
                            dbs.printf(ANSI_ESCAPE "1;36m");
                            dbs.println("# split %s %i %s", tlsadvisor->nameof_tls_handshake(desc.hstype).c_str(), desc.hsseq,
                                        tlsadvisor->nameof_direction(dir, 1).c_str());
                            dbs.printf(ANSI_ESCAPE "0m");
                            dump_memory(stream + fragoffset, fragsize, &dbs, 16, 3, 0, dump_notrunc);
                        });
                    }
#endif
                    uint32 mask = splitter_flag_t::splitter_new_segment;
                    if (dtls_record_publisher_multi_handshakes & get_flags()) {
                        // record consist of handshakes in the segment
                    } else {
                        // each handshake starts a new record (easy to control max record size)
                        mask |= splitter_flag_t::splitter_new_group;
                    }
                    if (mask & flags) {
                        auto rec_built = builder.set(session).set(rctype).set(dir).construct().build();
                        records.push_back(rec_built);
                    }
                    auto rec_fragmented = *records.rbegin();
                    auto hs_fragmented = new dtls_handshake_fragmented(desc.hstype, session);  // do not change sequence (handshake)
                    hs_fragmented->prepare_fragment(stream, t_narrow_cast(size), desc.hsseq, t_narrow_cast(fragoffset), t_narrow_cast(fragsize));
                    *rec_fragmented << hs_fragmented;
                };

                if (tls_content_type_t::handshake == rctype) {
                    tls_record_handshake* rec_handshake = static_cast<tls_record_handshake*>(record);
                    // rec_handshake->set_flags(dont_control_dtls_sequence);  // do not change epoch, sequence (record)

                    // split handshake
                    ret = rec_handshake->get_handshakes().for_each(lambda_handshake);
                    if (errorcode_t::success != ret) {
                        __leave2;
                    }
                    // generate record
                    spl.run(lambda_split);

                    // write record
                    for (auto& item : records) {
                        binary_t bin;
                        item->write(dir, bin);
                        container.push_back(std::move(bin));
                        item->release();
                    }
                } else {
                    binary_t bin;
                    ret = record->write(dir, bin);
                    container.push_back(std::move(bin));
                }
            }
        }
        __finally2 { record->release(); }
    }
    __finally2 {}
    return ret;
}

return_t dtls_record_publisher::publish(tls_record* record, tls_direction_t dir, std::function<void(tls_session*, binary_t&)> func) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == record || nullptr == func) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        std::list<binary_t> container;
        ret = publish(record, dir, container);
        if (errorcode_t::success != ret) {
            __leave2;
        }
        for (auto& item : container) {
            if (item.size() > get_max_size()) {
                ret = errorcode_t::exceed;
                break;
            }
        }
        if (errorcode_t::success != ret) {
            __leave2;
        }
        for (auto& item : container) {
            func(get_session(), item);
        }
    }
    __finally2 {}
    return ret;
}

return_t dtls_record_publisher::publish(tls_records* records, tls_direction_t dir, std::function<void(tls_session*, binary_t&)> func) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == records || nullptr == func) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        std::list<binary_t> container;
        std::list<std::queue<binary_t>> temp;
        std::queue<binary_t> q;
        size_t size = 0;
        auto lambda = [this, &dir, &container](tls_record* record) -> return_t { return publish(record, dir, container); };
        ret = records->for_each(lambda);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        for (auto& item : container) {
            auto isize = item.size();
            if (isize > get_max_size()) {
                ret = errorcode_t::exceed;
                break;
            }
            if ((false == q.empty()) && (size + isize > get_max_size())) {
                temp.push_back(std::move(q));
                q = std::queue<binary_t>();
                size = 0;
            }
            q.push(std::move(item));
            size += isize;
        }
        if (errorcode_t::success != ret) {
            __leave2;
        }
        if (false == q.empty()) {
            temp.push_back(std::move(q));
        }

        for (auto& qitem : temp) {
            auto qsize = qitem.size();
            if (1 == qsize) {
                func(get_session(), qitem.front());
                qitem.pop();
            } else {
                binary_t bin;
                for (; false == qitem.empty(); qitem.pop()) {
                    binary_append(bin, qitem.front());
                }
                func(get_session(), bin);
            }
        }
    }
    __finally2 {}
    return ret;
}

void dtls_record_publisher::set_session(tls_session* session) {
    if (nullptr == session) {
        throw exception(errorcode_t::no_session);
    }

    _session = session;
}

tls_session* dtls_record_publisher::get_session() const { return _session; }

void dtls_record_publisher::set_flags(uint32 flags) { _flags = flags; }

uint32 dtls_record_publisher::get_flags() const { return _flags; }

}  // namespace net
}  // namespace hotplace
