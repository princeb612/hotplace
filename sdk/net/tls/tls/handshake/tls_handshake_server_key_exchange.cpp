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
#include <sdk/base/unittest/trace.hpp>
#include <sdk/crypto/basic/crypto_advisor.hpp>
#include <sdk/crypto/basic/crypto_keychain.hpp>
#include <sdk/crypto/basic/crypto_sign.hpp>
#include <sdk/crypto/basic/evp_key.hpp>
#include <sdk/io/basic/payload.hpp>
#include <sdk/net/tls/tls/handshake/tls_handshake_server_key_exchange.hpp>
#include <sdk/net/tls/tls_advisor.hpp>
#include <sdk/net/tls/tls_protection.hpp>
#include <sdk/net/tls/tls_session.hpp>

namespace hotplace {
namespace net {

constexpr char constexpr_curve_info[] = "curve info";
constexpr char constexpr_curve[] = "curve";
constexpr char constexpr_pubkey_len[] = "public key len";
constexpr char constexpr_pubkey[] = "public key";
constexpr char constexpr_signature[] = "signature";
constexpr char constexpr_sig_len[] = "signature len";
constexpr char constexpr_sig[] = "computed signature";

tls_handshake_server_key_exchange::tls_handshake_server_key_exchange(tls_session* session) : tls_handshake(tls_hs_server_key_exchange, session) {}

return_t tls_handshake_server_key_exchange::do_postprocess(tls_direction_t dir, const byte_t* stream, size_t size) {
    return_t ret = errorcode_t::success;
    __try2 {
        auto session = get_session();
        if (nullptr == session) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }
        auto hspos = offsetof_header();
        auto& protection = session->get_tls_protection();
        auto hssize = get_size();

        protection.update_transcript_hash(session, stream + hspos, hssize);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_handshake_server_key_exchange::do_read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos) {
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
            auto& keyexchange = protection.get_keyexchange();
            crypto_advisor* advisor = crypto_advisor::get_instance();
            tls_advisor* tlsadvisor = tls_advisor::get_instance();

            size_t hspos = pos;
            uint8 curve_info = 0;
            uint16 curve = 0;
            uint8 pubkey_len = 0;
            binary_t pubkey;
            uint16 sigalg = 0;
            uint16 sig_len = 0;
            binary_t sig;

            // RFC 5246 7.4.3.  Server Key Exchange Message
            {
                payload pl;
                pl << new payload_member(uint8(0), constexpr_curve_info)        //
                   << new payload_member(uint16(0), true, constexpr_curve)      //
                   << new payload_member(uint8(0), constexpr_pubkey_len)        //
                   << new payload_member(binary_t(), constexpr_pubkey)          //
                   << new payload_member(uint16(0), true, constexpr_signature)  //
                   << new payload_member(uint16(0), true, constexpr_sig_len)    //
                   << new payload_member(binary_t(), constexpr_sig);            //
                pl.set_reference_value(constexpr_pubkey, constexpr_pubkey_len);
                pl.set_reference_value(constexpr_sig, constexpr_sig_len);
                pl.read(stream, size, pos);

                curve_info = pl.t_value_of<uint8>(constexpr_curve_info);
                curve = pl.t_value_of<uint16>(constexpr_curve);
                pubkey_len = pl.t_value_of<uint8>(constexpr_pubkey_len);
                pl.get_binary(constexpr_pubkey, pubkey);
                sigalg = pl.t_value_of<uint16>(constexpr_signature);
                sig_len = pl.t_value_of<uint16>(constexpr_sig_len);
                pl.get_binary(constexpr_sig, sig);
            }

            auto pkey = keyexchange.find(KID_TLS_SERVER_CERTIFICATE_PUBLIC);
            if (nullptr == pkey) {
                ret = errorcode_t::invalid_context;
                __leave2;
            }

            {
                // RFC 8422, EC Curve Type, 3, "named_curve", see ec_curve_type_desc (tls_ec_curve_type_desc_t)
                // 1 explicit_prime
                // 2 explicit_char2
                // 3 named_curve
                if (3 == curve_info) {
                    crypto_keychain keychain;
                    auto hint = advisor->hintof_tls_group(curve);
                    uint32 nid = nidof(hint);
                    if (nid) {
                        ret = keychain.add_ec(&keyexchange, nid, pubkey, binary_t(), binary_t(), keydesc(KID_TLS_SERVER_KEY_EXCHANGE));
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

                crypto_sign_builder builder;
                auto sign = builder.set_tls_sign_scheme(sigalg).build();
                if (sign) {
                    ret = sign->verify(pkey, message, sig);
                    sign->release();
                } else {
                    ret = errorcode_t::not_supported;
                }
            }

            if (istraceable()) {
                basic_stream dbs;
                dbs.autoindent(2);
                dbs.printf("> %s %i (%s)\n", constexpr_curve_info, curve_info, tlsadvisor->ec_curve_type_string(curve_info).c_str());
                dbs.printf("> %s 0x%04x %s\n", constexpr_curve, curve, tlsadvisor->supported_group_name(curve).c_str());
                dbs.printf("> %s\n", constexpr_pubkey);
                dbs.printf(" > %s %i\n", constexpr_pubkey_len, pubkey_len);
                dump_memory(pubkey, &dbs, 16, 4, 0x0, dump_notrunc);
                dbs.printf("> %s\n", constexpr_signature);
                dbs.printf(" > 0x%04x %s\n", sigalg, tlsadvisor->signature_scheme_name(sigalg).c_str());
                dbs.printf(" > %s %i\n", constexpr_sig_len, sig_len);
                dump_memory(sig, &dbs, 16, 3, 0x0, dump_notrunc);
                dbs.autoindent(0);

                trace_debug_event(category_net, net_event_tls_read, &dbs);
            }
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_handshake_server_key_exchange::do_write_body(tls_direction_t dir, binary_t& bin) {
    return_t ret = errorcode_t::success;
    auto session = get_session();
    auto& protection = session->get_tls_protection();
    auto& keyexchange = protection.get_keyexchange();
    auto& protection_context = protection.get_protection_context();
    auto advisor = crypto_advisor::get_instance();
    auto tlsadvisor = tls_advisor::get_instance();
    uint8 curve_info = 3;  // named curvev
    uint16 curve = 0;
    binary_t pubkey;
    binary_t sig;
    keydesc desc(KID_TLS_SERVER_KEY_EXCHANGE);
    crypto_keychain keychain;

    {
        auto lambda = [&](uint16 group, bool* ctrl) -> void {
            auto hint = advisor->hintof_tls_group(group);
            if (hint && hint->tlsgroup) {
                auto kty = hint->kty;
                auto category = hint->category;
                auto nid = hint->nid;
                bool stop = false;
                if (kty_ec == kty) {
                    keychain.add_ec(&keyexchange, nid, desc);
                    auto pkey = keyexchange.find(KID_TLS_SERVER_KEY_EXCHANGE);
                    if (pkey) {
                        binary_t temp;
                        keyexchange.ec_uncompressed_key(pkey, pubkey, temp);
                        curve = group;
                        stop = true;
                    }
                } else if (kty_okp == kty) {
                    keychain.add_ec(&keyexchange, nid, desc);
                    auto pkey = keyexchange.find(KID_TLS_SERVER_KEY_EXCHANGE);
                    if (pkey) {
                        binary_t temp;
                        keyexchange.get_public_key(pkey, pubkey, temp);
                        curve = group;
                        stop = true;
                    }
                }
                *ctrl = stop;
            }
        };
        protection_context.for_each_supported_groups(lambda);
    }

    auto pkey_cert = keyexchange.find(KID_TLS_SERVER_CERTIFICATE_PRIVATE);
    auto kty_cert = typeof_crypto_key(pkey_cert);

    uint16 sigalg = 0;
    {
        auto lambda = [&](uint16 sigscheme, bool* ctrl) -> void {
            auto hint = tlsadvisor->hintof_signature_scheme(sigscheme);
            bool stop = false;
            if (hint) {
                if ((hint->kty == kty_cert) && (kty_unknown != kty_cert)) {
                    sigalg = sigscheme;
                    stop = true;
                }
            }
            *ctrl = stop;
        };
        protection_context.for_each_signature_algorithms(lambda);
    }

    {
        // sign(client_hello_random + server_hello_random + curve_info + public_key)
        binary_t message;
        binary_append(message, protection.get_item(tls_context_client_hello_random));
        binary_append(message, protection.get_item(tls_context_server_hello_random));
        binary_append(message, uint8(curve_info));
        binary_append(message, uint16(curve), hton16);
        binary_append(message, uint8(pubkey.size()));
        binary_append(message, pubkey);

        crypto_sign_builder builder;
        auto sign = builder.set_tls_sign_scheme(sigalg).build();
        if (sign) {
            crypto_key& key = session->get_tls_protection().get_keyexchange();
            ret = sign->sign(pkey_cert, message, sig);
            sign->release();
        } else {
            ret = errorcode_t::not_supported;
        }
    }

    {
        payload pl;
        pl << new payload_member(uint8(curve_info), constexpr_curve_info)      //
           << new payload_member(uint16(curve), true, constexpr_curve)         //
           << new payload_member(uint8(pubkey.size()), constexpr_pubkey_len)   //
           << new payload_member(pubkey, constexpr_pubkey)                     //
           << new payload_member(uint16(sigalg), true, constexpr_signature)    //
           << new payload_member(uint16(sig.size()), true, constexpr_sig_len)  //
           << new payload_member(sig, constexpr_sig);
        pl.write(bin);
    }

    if (istraceable()) {
        basic_stream dbs;
        dbs.autoindent(2);
        dbs.printf("> %s %i (%s)\n", constexpr_curve_info, curve_info, tlsadvisor->ec_curve_type_string(curve_info).c_str());
        dbs.printf("> %s 0x%04x %s\n", constexpr_curve, curve, tlsadvisor->supported_group_name(curve).c_str());
        dbs.printf("> %s\n", constexpr_pubkey);
        dbs.printf(" > %s %zi\n", constexpr_pubkey_len, pubkey.size());
        dump_memory(pubkey, &dbs, 16, 4, 0, dump_notrunc);
        dbs.printf("> %s\n", constexpr_signature);
        dbs.printf(" > 0x%04x %s\n", sigalg, tlsadvisor->signature_scheme_name(sigalg).c_str());
        dbs.printf(" > %s %zi\n", constexpr_sig_len, sig.size());
        dump_memory(sig, &dbs, 16, 3, 0, dump_notrunc);
        dbs.autoindent(0);

        trace_debug_event(category_net, net_event_tls_write, &dbs);
    }

    return ret;
}

}  // namespace net
}  // namespace hotplace
