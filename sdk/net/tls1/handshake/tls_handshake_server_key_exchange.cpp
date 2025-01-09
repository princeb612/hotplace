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
#include <sdk/crypto/basic/crypto_advisor.hpp>
#include <sdk/crypto/basic/crypto_keychain.hpp>
#include <sdk/crypto/crypto/crypto_sign.hpp>
#include <sdk/io/basic/payload.hpp>
#include <sdk/net/tls1/handshake/tls_handshake_server_key_exchange.hpp>
#include <sdk/net/tls1/tls.hpp>
#include <sdk/net/tls1/tls_advisor.hpp>
#include <sdk/net/tls1/tls_session.hpp>

namespace hotplace {
namespace net {

tls_handshake_server_key_exchange::tls_handshake_server_key_exchange(tls_session* session) : tls_handshake(tls_hs_server_key_exchange, session) {}

return_t tls_handshake_server_key_exchange::do_handshake(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos, stream_t* debugstream) {
    return_t ret = errorcode_t::success;
    __try2 {
        auto session = get_session();
        if (nullptr == session) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }
        auto hspos = get_header_range().begin;
        auto hdrsize = get_header_size();
        auto& protection = session->get_tls_protection();

        {
            ret = do_read(dir, stream, size, pos, debugstream);

            protection.calc_transcript_hash(session, stream + hspos, hdrsize);
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_handshake_server_key_exchange::do_read(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos, stream_t* debugstream) {
    return_t ret = errorcode_t::success;
    __try2 {
        auto session = get_session();
        if (nullptr == session) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }
        if (nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        {
            auto& protection = session->get_tls_protection();
            crypto_advisor* advisor = crypto_advisor::get_instance();
            tls_advisor* tlsadvisor = tls_advisor::get_instance();

            size_t hspos = pos;
            uint8 curve_info = 0;
            uint16 curve = 0;
            uint8 pubkey_len = 0;
            binary_t pubkey;
            uint16 signature = 0;
            uint16 sig_len = 0;
            binary_t sig;

            constexpr char constexpr_curve_info[] = "curve info";
            constexpr char constexpr_curve[] = "curve";
            constexpr char constexpr_pubkey_len[] = "public key len";
            constexpr char constexpr_pubkey[] = "public key";
            constexpr char constexpr_signature[] = "signature";
            constexpr char constexpr_sig_len[] = "signature len";
            constexpr char constexpr_sig[] = "computed signature";

            // RFC 5246 7.4.3.  Server Key Exchange Message
            {
                payload pl;
                pl << new payload_member(uint8(0), constexpr_curve_info) << new payload_member(uint16(0), true, constexpr_curve)
                   << new payload_member(uint8(0), constexpr_pubkey_len) << new payload_member(binary_t(), constexpr_pubkey)
                   << new payload_member(uint16(0), true, constexpr_signature) << new payload_member(uint16(0), true, constexpr_sig_len)
                   << new payload_member(binary_t(), constexpr_sig);
                pl.set_reference_value(constexpr_pubkey, constexpr_pubkey_len);
                pl.set_reference_value(constexpr_sig, constexpr_sig_len);
                pl.read(stream, size, pos);

                curve_info = pl.t_value_of<uint8>(constexpr_curve_info);
                curve = pl.t_value_of<uint16>(constexpr_curve);
                pubkey_len = pl.t_value_of<uint8>(constexpr_pubkey_len);
                pl.get_binary(constexpr_pubkey, pubkey);
                signature = pl.t_value_of<uint16>(constexpr_signature);
                sig_len = pl.t_value_of<uint16>(constexpr_sig_len);
                pl.get_binary(constexpr_sig, sig);
            }

            {
                // RFC 8422, EC Curve Type, 3, "named_curve", see ec_curve_type_desc (tls_ec_curve_type_desc_t)
                // 1 explicit_prime
                // 2 explicit_char2
                // 3 named_curve
                if (3 == curve_info) {
                    crypto_keychain keychain;
                    auto& keyexchange = protection.get_keyexchange();
                    auto hint = advisor->hintof_tls_group(curve);
                    uint32 nid = nidof(hint);
                    if (nid) {
                        ret = keychain.add_ec(&keyexchange, nid, pubkey, binary_t(), binary_t(), keydesc("SKE"));
                    } else {
                        ret = errorcode_t::not_supported;
                    }
                }
            }

            {
                // hash(client_hello_random + server_hello_random + curve_info + public_key)
                binary_t message;
                binary_append(message, protection.get_item(tls_context_client_hello_random));
                binary_append(message, protection.get_item(tls_context_server_hello_random));
                binary_append(message, stream + hspos, 3);
                binary_append(message, pubkey_len);
                binary_append(message, pubkey);

                auto sign = session->get_tls_protection().get_crypto_sign(signature);
                if (sign) {
                    crypto_key& key = session->get_tls_protection().get_keyexchange();
                    auto pkey = key.any();
                    ret = sign->verify(pkey, message, sig);
                    sign->release();
                } else {
                    ret = errorcode_t::not_supported;
                }
            }

            if (debugstream) {
                debugstream->autoindent(1);
                debugstream->printf(" > %s %i (%s)\n", constexpr_curve_info, curve_info, tlsadvisor->ec_curve_type_string(curve_info).c_str());
                debugstream->printf(" > %s 0x%04x %s\n", constexpr_curve, curve, tlsadvisor->supported_group_string(curve).c_str());
                debugstream->printf(" > %s %i\n", constexpr_pubkey_len, pubkey_len);
                dump_memory(pubkey, debugstream, 16, 3, 0x0, dump_notrunc);
                debugstream->printf(" > %s 0x%04x %s\n", constexpr_signature, signature, tlsadvisor->signature_scheme_string(signature).c_str());
                debugstream->printf(" > %s %i\n", constexpr_sig_len, sig_len);
                dump_memory(sig, debugstream, 16, 3, 0x0, dump_notrunc);
                debugstream->autoindent(0);
            }
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

}  // namespace net
}  // namespace hotplace
