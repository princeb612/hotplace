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
#include <sdk/base/stream/basic_stream.hpp>
#include <sdk/base/unittest/trace.hpp>
#include <sdk/crypto/basic/crypto_keychain.hpp>
#include <sdk/crypto/basic/evp_key.hpp>
#include <sdk/io/basic/payload.hpp>
#include <sdk/net/tls/tls/handshake/tls_handshake_client_key_exchange.hpp>
#include <sdk/net/tls/tls/tls.hpp>
#include <sdk/net/tls/tls_advisor.hpp>
#include <sdk/net/tls/tls_session.hpp>

namespace hotplace {
namespace net {

constexpr char constexpr_pubkey_len[] = "public key len";
constexpr char constexpr_pubkey[] = "public key";

tls_handshake_client_key_exchange::tls_handshake_client_key_exchange(tls_session* session) : tls_handshake(tls_hs_client_key_exchange, session) {}

return_t tls_handshake_client_key_exchange::do_postprocess(tls_direction_t dir, const byte_t* stream, size_t size) {
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

        {
            protection.update_transcript_hash(session, stream + hspos, hssize);
            protection.calc(session, tls_hs_client_key_exchange, dir);
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_handshake_client_key_exchange::do_read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos) {
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
            uint8 pubkey_len = 0;
            binary_t pubkey;
            {
                payload pl;
                pl << new payload_member(uint8(0), constexpr_pubkey_len) << new payload_member(binary_t(), constexpr_pubkey);
                pl.set_reference_value(constexpr_pubkey, constexpr_pubkey_len);
                pl.read(stream, size, pos);

                pubkey_len = pl.t_value_of<uint8>(constexpr_pubkey_len);
                pl.get_binary(constexpr_pubkey, pubkey);
            }

            {
                // kty, nid from server_key_exchange
                auto& protection = session->get_tls_protection();
                auto& keyexchange = protection.get_keyexchange();
                crypto_keychain keychain;
                uint32 nid = 0;
                auto pkey_ske = keyexchange.find(KID_TLS_SERVER_KEY_EXCHANGE);
                crypto_kty_t kty = typeof_crypto_key(pkey_ske);
                nidof_evp_pkey(pkey_ske, nid);
                if (nid) {
                    keydesc desc(KID_TLS_CLIENT_KEY_EXCHANGE);
                    if (kty_ec == kty || kty_okp == kty) {
                        ret = keychain.add_ec(&keyexchange, nid, pubkey, binary_t(), binary_t(), desc);
                    } else if (kty_dh == kty) {
                        ret = keychain.add_dh(&keyexchange, nid, pubkey, binary_t(), desc);
                    } else {
                        ret = errorcode_t::not_supported;
                    }
                } else {
                    ret = errorcode_t::not_supported;
                }
            }

            if (istraceable()) {
                basic_stream dbs;
                dbs.autoindent(1);
                dbs.printf(" > %s %i\n", constexpr_pubkey_len, pubkey_len);
                dbs.printf(" > %s\n", constexpr_pubkey);
                dump_memory(pubkey, &dbs, 16, 3, 0x0, dump_notrunc);
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

return_t tls_handshake_client_key_exchange::do_write_body(tls_direction_t dir, binary_t& bin) {
    return_t ret = errorcode_t::success;

    __try2 {
        auto session = get_session();
        auto& protection = session->get_tls_protection();
        auto& keyexchange = protection.get_keyexchange();
        auto pkey_ske = keyexchange.find(KID_TLS_SERVER_KEY_EXCHANGE);
        {
            // kty, nid from server_key_exchange
            crypto_keychain keychain;
            uint32 nid = 0;
            crypto_kty_t kty = typeof_crypto_key(pkey_ske);
            nidof_evp_pkey(pkey_ske, nid);
            if (nid) {
                keydesc desc(KID_TLS_CLIENT_KEY_EXCHANGE);
                if (kty_rsa == kty) {
                    ret = keychain.add_rsa(&keyexchange, nid, 2048, desc);
                } else if (kty_ec == kty || kty_okp == kty) {
                    ret = keychain.add_ec(&keyexchange, nid, desc);
                } else if (kty_dh == kty) {
                    ret = keychain.add_dh(&keyexchange, nid, desc);
                } else {
                    ret = errorcode_t::not_supported;
                    __leave2;
                }
            } else {
                ret = errorcode_t::not_supported;
                __leave2;
            }
        }

        binary_t pubkey;
        auto pkey_cke = keyexchange.find(KID_TLS_CLIENT_KEY_EXCHANGE);
        if (pkey_cke) {
            crypto_kty_t kty = typeof_crypto_key(pkey_cke);
            if (kty_ec == kty) {
                binary_t temp;
                keyexchange.ec_uncompressed_key(pkey_cke, pubkey, temp);
            } else if (kty_okp == kty) {
                binary_t temp;
                keyexchange.get_public_key(pkey_cke, pubkey, temp);
            }
        }

        {
            payload pl;
            pl << new payload_member(uint8(pubkey.size()), constexpr_pubkey_len) << new payload_member(pubkey, constexpr_pubkey);
            pl.write(bin);
        }

        if (istraceable()) {
            basic_stream dbs;
            dbs.printf("> SKE\n");
            dump_key(pkey_ske, &dbs, 16, 3, dump_notrunc);
            dbs.printf("> CKE\n");
            dump_key(pkey_cke, &dbs, 16, 3, dump_notrunc);
            trace_debug_event(category_net, net_event_tls_read, &dbs);
        }
    }
    __finally2 {}
    return ret;
}

}  // namespace net
}  // namespace hotplace
