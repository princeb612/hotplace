/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 */

#include <sdk/base/basic/dump_memory.hpp>
#include <sdk/base/unittest/trace.hpp>
#include <sdk/crypto/basic/openssl_crypt.hpp>
#include <sdk/io/basic/payload.hpp>
#include <sdk/net/tls/quic/frame/quic_frames.hpp>
#include <sdk/net/tls/quic/packet/quic_packet_1rtt.hpp>
#include <sdk/net/tls/quic/quic.hpp>
#include <sdk/net/tls/quic_session.hpp>
#include <sdk/net/tls/tls_session.hpp>

namespace hotplace {
namespace net {

constexpr char constexpr_payload[] = "pn + payload";
constexpr char constexpr_tag[] = "tag";

quic_packet_1rtt::quic_packet_1rtt(tls_session* session) : quic_packet(quic_packet_type_1_rtt, session) {}

quic_packet_1rtt::quic_packet_1rtt(const quic_packet_1rtt& rhs) : quic_packet(rhs) {}

quic_packet_1rtt::~quic_packet_1rtt() {}

return_t quic_packet_1rtt::do_read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos, size_t& pos_unprotect) {
    return_t ret = errorcode_t::success;
    __try2 {
        auto session = get_session();
        if ((nullptr == session) || (false == is_unidirection(dir))) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }

        auto& protection = session->get_tls_protection();
        auto tagsize = protection.get_tag_size();

        binary_t bin_unprotected_header;
        binary_t bin_protected_header;

        size_t ppos = pos;
        size_t offset_pnpayload = 0;
        // byte_t ht = stream[pos];

        {
            payload pl;
            pl << new payload_member(binary_t(), constexpr_payload)  //
               << new payload_member(binary_t(), constexpr_tag);
            pl.reserve(constexpr_tag, tagsize);
            pl.read(stream, size, pos);

            pl.get_binary(constexpr_payload, _payload);
            pl.get_binary(constexpr_tag, _tag);

            offset_pnpayload = pl.offset_of(constexpr_payload);

            pos_unprotect = (ppos + offset_pnpayload + 4);
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t quic_packet_1rtt::do_read(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos, size_t pos_unprotect) {
    return_t ret = errorcode_t::success;
    __try2 {
        auto session = get_session();

        ret = do_unprotect(dir, stream, size, pos_unprotect, protection_application);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        dump();

        size_t tpos = 0;
        ret = get_quic_frames().read(dir, &_payload[0], _payload.size(), tpos);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        session->get_quic_session().get_pkns(protection_application).add(get_pn());
    }
    __finally2 {}
    return ret;
}

return_t quic_packet_1rtt::do_write_body(tls_direction_t dir, binary_t& body) {
    return_t ret = errorcode_t::success;
    get_quic_frames().write(dir, body);
    return ret;
}

return_t quic_packet_1rtt::do_write(tls_direction_t dir, binary_t& header, binary_t& ciphertext, binary_t& tag) {
    return_t ret = errorcode_t::success;
    __try2 {
        auto session = get_session();
        if (nullptr == session) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }

        auto& protection = session->get_tls_protection();
        auto tagsize = protection.get_tag_size();

        binary_t bin_unprotected_header = std::move(header);
        binary_t bin_protected_header;
        uint8 pn_length = 0;
        uint64 len = 0;
        binary_t bin_pn;

        // unprotected header
        {
            // protected header
            bin_protected_header = bin_unprotected_header;

            // packet number length + payload size + AEAD tag size
            pn_length = get_pn_length();
            len = pn_length + get_payload().size() + tagsize;

            // packet number
            binary_load(bin_pn, pn_length, _pn, hton32);

            // unprotected header
            payload pl;
            pl << new payload_member(bin_pn);
            pl.write(bin_unprotected_header);
        }

        /**
         * RFC 9001 5.4.2.  Header Protection Sample
         *
         *  protected payload is at least 4 bytes longer than the sample required for header protection
         *
         *  in sampling header ciphertext for header protection, the Packet Number field is
         *  assumed to be 4 bytes long (its maximum possible encoded length).
         */
        if (is_unidirection(dir) && (get_payload().size() > 0)) {
            binary_t bin_ciphertext;
            binary_t bin_tag;
            binary_t bin_mask;

            // AEAD
            ret = protection.encrypt(session, dir, get_payload(), bin_ciphertext, bin_unprotected_header, bin_tag, protection_application);
            if (errorcode_t::success != ret) {
                __leave2;
            }

            // Header Protection
            {
                uint8 ht = _ht;
                ret = header_protect(dir, bin_ciphertext, protection_application, ht, pn_length, bin_pn, bin_protected_header);
                if (errorcode_t::success != ret) {
                    __leave2;
                }

                // encode packet number
                payload pl;
                pl << new payload_member(bin_pn);  //

                // protected header
                pl.write(bin_protected_header);
            }

            header = std::move(bin_protected_header);
            ciphertext = std::move(bin_ciphertext);
            tag = std::move(bin_tag);
        } else {
            header = std::move(bin_unprotected_header);
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

}  // namespace net
}  // namespace hotplace
