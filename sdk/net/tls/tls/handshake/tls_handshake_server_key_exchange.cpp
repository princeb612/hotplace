/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   tls_handshake_server_key_exchange.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/base/basic/dump_memory.hpp>
#include <hotplace/sdk/base/basic/function_pipeline.hpp>
#include <hotplace/sdk/base/system/trace.hpp>
#include <hotplace/sdk/crypto/basic/crypto_advisor.hpp>
#include <hotplace/sdk/crypto/basic/crypto_keychain.hpp>
#include <hotplace/sdk/crypto/basic/crypto_sign.hpp>
#include <hotplace/sdk/crypto/basic/evp_pkey.hpp>
#include <hotplace/sdk/crypto/basic/openssl_sign.hpp>
#include <hotplace/sdk/io/basic/payload.hpp>
#include <hotplace/sdk/net/tls/tls/handshake/tls_handshake_server_key_exchange.hpp>
#include <hotplace/sdk/net/tls/tls_advisor.hpp>
#include <hotplace/sdk/net/tls/tls_protection.hpp>
#include <hotplace/sdk/net/tls/tls_session.hpp>

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

tls_handshake_server_key_exchange::~tls_handshake_server_key_exchange() {}

return_t tls_handshake_server_key_exchange::do_preprocess(tls_direction_t dir) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (from_server != dir) {
            ret = errorcode_t::bad_request;
            __leave2_trace(ret);
        }

        // TLS 1.2

        auto session = get_session();
        auto session_status = session->get_session_status();
        if (0 == (session_status_server_cert & session_status)) {
            session->push_alert(dir, tls_alertlevel_fatal, tls_alertdesc_unexpected_message);
            session->reset_session_status();
            ret = errorcode_t::error_handshake;
            __leave2_trace(ret);
        }
    }
    __finally2 {}
    return ret;
}

return_t tls_handshake_server_key_exchange::do_postprocess(tls_direction_t dir, const byte_t* stream, size_t size) {
    return_t ret = errorcode_t::success;
    __try2 {
        auto session = get_session();
        auto hspos = offsetof_header();
        auto& protection = session->get_tls_protection();
        auto hssize = get_size();

        protection.update_transcript_hash(session, stream + hspos, hssize);
        session->update_session_status(session_status_server_key_exchange);
    }
    __finally2 {}
    return ret;
}

return_t tls_handshake_server_key_exchange::do_read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos) {
    function_pipeline<return_t> pipeline;
#if defined DEBUG
    uint16 sig_len = 0;
#endif
    auto session = get_session();
    auto& protection = session->get_tls_protection();
    auto& secrets = protection.get_secrets();
    auto& tlskey = protection.get_key();
    // crypto_advisor *advisor = crypto_advisor::get_instance();
    tls_advisor* tlsadvisor = tls_advisor::get_instance();

    size_t hspos = pos;
    uint8 curve_info = 0;
    uint16 curve = 0;
    uint8 pubkey_len = 0;
    binary_t pubkey;
    uint16 sigalg = 0;
    binary_t sig;

    pipeline  //
        .test_not_fail()
        .test_parameter([&]() -> bool { return (nullptr != stream) && (pos < size); })
        .run_trycatch([&]() -> return_t {
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

                auto rc = pl.read(stream, size, pos);
                if (false == error_traits<return_t>::is_not_fail(rc)) {
                    return rc;
                }

                curve_info = pl.t_value_of<uint8>(constexpr_curve_info);
                curve = pl.t_value_of<uint16>(constexpr_curve);
                pubkey_len = pl.t_value_of<uint8>(constexpr_pubkey_len);
                pl.get_binary(constexpr_pubkey, pubkey);
                sigalg = pl.t_value_of<uint16>(constexpr_signature);
#if defined DEBUG
                sig_len = pl.t_value_of<uint16>(constexpr_sig_len);
#endif
                pl.get_binary(constexpr_sig, sig);
            }
            return success;
        })
        .run([&]() -> return_t {
            return_t rc = success;

            auto pkey = tlsadvisor->get_key(session, KID_TLS_SERVER_CERTIFICATE_PUBLIC);
            if (nullptr == pkey) {
                return errorcode_t::not_found;
            }

            // RFC 8422, EC Curve Type, 3, "named_curve"
            // 1 explicit_prime
            // 2 explicit_char2
            // 3 named_curve
            if (3 == curve_info) {
                crypto_keyexchange keyexchange;
                rc = keyexchange.keystore((tls_group_t)curve, &tlskey, KID_TLS_SERVER_KEY_EXCHANGE, pubkey);
                if (success != rc) {
                    return rc;
                }
            }

            // hash(client_hello_random + server_hello_random + curve_info + public_key)
            binary_t message;
            binary_append(message, secrets.get(tls_context_client_hello_random));
            binary_append(message, secrets.get(tls_context_server_hello_random));
            binary_append(message, stream + hspos, 3);
            binary_append(message, pubkey_len);
            binary_append(message, pubkey);

            crypto_sign_builder builder;
            auto sign = builder.set_tls_sign_scheme(sigalg).build();
            if (sign) {
                rc = sign->verify(pkey, message, sig, sign_flag_format_der);
                sign->release();
            } else {
                rc = errorcode_t::not_available;
            }

            return rc;
        })
        .walk_always([&](return_t rc) -> void {
#if defined DEBUG
            if (istraceable(trace_category_net)) {
                trace_debug_event(trace_category_net, trace_event_tls_handshake, [&](basic_stream& dbs) -> void {
                    dbs.autoindent(2);
                    dbs.println("> %s %i (%s)", constexpr_curve_info, curve_info, tlsadvisor->nameof_ec_curve_type(curve_info).c_str());
                    dbs.println("> %s 0x%04x %s", constexpr_curve, curve, tlsadvisor->nameof_group(curve).c_str());
                    dbs.println("> %s", constexpr_pubkey);
                    dbs.println(" > %s %i", constexpr_pubkey_len, pubkey_len);
                    if (check_trace_level(loglevel_debug)) {
                        dump_memory(pubkey, &dbs, 16, 4, 0x0, dump_notrunc);
                    }
                    dbs.println("> %s " ANSI_ESCAPE "1;33m%s" ANSI_ESCAPE "0m", constexpr_signature, (errorcode_t::success == rc) ? "true" : "false");
                    dbs.println(" > 0x%04x %s", sigalg, tlsadvisor->nameof_signature_scheme(sigalg).c_str());
                    dbs.println(" > %s %i", constexpr_sig_len, sig_len);
                    if (check_trace_level(loglevel_debug)) {
                        dump_memory(sig, &dbs, 16, 3, 0x0, dump_notrunc);
                    }
                    dbs.autoindent(0);
                });
            }
#endif
        });
    return pipeline.result();
}

return_t tls_handshake_server_key_exchange::do_write_body(tls_direction_t dir, binary_t& bin) {
    function_pipeline<return_t> pipeline;

    pipeline  //
        .run_trycatch([&]() -> return_t {
            return_t rc = success;
            auto session = get_session();
            auto& protection = session->get_tls_protection();
            auto& secrets = protection.get_secrets();
            auto& tlskey = protection.get_key();
            auto& protection_context = protection.get_protection_context();
            auto advisor = crypto_advisor::get_instance();
            auto tlsadvisor = tls_advisor::get_instance();
            uint8 curve_info = 3;  // named curvev
            uint16 curve = 0;
            binary_t pubkey;
            binary_t sig;
            crypto_keychain keychain;
            crypto_keyexchange keyexchange;

            {
                auto lambda = [&](uint16 group, bool* ctrl) -> void {
                    auto hint = advisor->hintof_curve_tls_group(group);
                    if (hint && hint->tlsgroup) {
                        keyexchange.keygen((tls_group_t)group, &tlskey, KID_TLS_SERVER_KEY_EXCHANGE);
                        keyexchange.keyshare((tls_group_t)group, &tlskey, KID_TLS_SERVER_KEY_EXCHANGE, pubkey);
                        curve = group;
                        *ctrl = true;  // stop
                    }
                };
                protection_context.for_each_supported_groups(lambda);
            }

            auto pkey_cert = tlsadvisor->get_key(session, KID_TLS_SERVER_CERTIFICATE_PRIVATE);
            auto kty_cert = ktyof_evp_pkey(pkey_cert);

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
                binary_append(message, secrets.get(tls_context_client_hello_random));
                binary_append(message, secrets.get(tls_context_server_hello_random));
                binary_append(message, uint8(curve_info));
                binary_append(message, uint16(curve), hton16);
                binary_append(message, uint8(pubkey.size()));
                binary_append(message, pubkey);

                crypto_sign_builder builder;
                auto sign = builder.set_tls_sign_scheme(sigalg).build();
                if (sign) {
                    rc = sign->sign(pkey_cert, message, sig, sign_flag_format_der);
                    sign->release();
                } else {
                    rc = errorcode_t::not_available;
                }
                if (success != rc) {
                    return rc;
                }
            }

#if defined DEBUG
            if (istraceable(trace_category_net)) {
                trace_debug_event(trace_category_net, trace_event_tls_handshake, [&](basic_stream& dbs) -> void {
                    dbs.autoindent(2);
                    dbs.println("> %s %i (%s)", constexpr_curve_info, curve_info, tlsadvisor->nameof_ec_curve_type(curve_info).c_str());
                    dbs.println("> %s 0x%04x %s", constexpr_curve, curve, tlsadvisor->nameof_group(curve).c_str());
                    dbs.println("> %s", constexpr_pubkey);
                    dbs.println(" > %s %zi", constexpr_pubkey_len, pubkey.size());
                    if (check_trace_level(loglevel_debug)) {
                        dump_memory(pubkey, &dbs, 16, 4, 0, dump_notrunc);
                    }
                    dbs.println("> %s", constexpr_signature);
                    dbs.println(" > 0x%04x %s", sigalg, tlsadvisor->nameof_signature_scheme(sigalg).c_str());
                    dbs.println(" > %s %zi", constexpr_sig_len, sig.size());
                    if (check_trace_level(loglevel_debug)) {
                        dump_memory(sig, &dbs, 16, 3, 0, dump_notrunc);
                    }
                    dbs.autoindent(0);
                });
            }
#endif

            {
                payload pl;
                pl << new payload_member(uint8(curve_info), constexpr_curve_info)      //
                   << new payload_member(uint16(curve), true, constexpr_curve)         //
                   << new payload_member(uint8(pubkey.size()), constexpr_pubkey_len)   //
                   << new payload_member(pubkey, constexpr_pubkey)                     //
                   << new payload_member(uint16(sigalg), true, constexpr_signature)    //
                   << new payload_member(uint16(sig.size()), true, constexpr_sig_len)  //
                   << new payload_member(sig, constexpr_sig);

                rc = pl.write(bin);
                if (false == error_traits<return_t>::is_not_fail(rc)) {
                    return rc;
                }
            }

            return success;
        });
    return pipeline.result();
}

}  // namespace net
}  // namespace hotplace
