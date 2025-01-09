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
#include <sdk/crypto/basic/crypto_keychain.hpp>
#include <sdk/crypto/basic/evp_key.hpp>
#include <sdk/io/basic/payload.hpp>
#include <sdk/net/tls1/handshake/tls_handshake_client_key_exchange.hpp>
#include <sdk/net/tls1/tls.hpp>
#include <sdk/net/tls1/tls_advisor.hpp>
#include <sdk/net/tls1/tls_session.hpp>

namespace hotplace {
namespace net {

tls_handshake_client_key_exchange::tls_handshake_client_key_exchange(tls_session* session) : tls_handshake(tls_hs_client_key_exchange, session) {}

return_t tls_handshake_client_key_exchange::do_handshake(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos, stream_t* debugstream) {
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

            protection.calc(session, tls_hs_client_key_exchange, dir);

            protection.calc_transcript_hash(session, stream + hspos, hdrsize);
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_handshake_client_key_exchange::do_read(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos, stream_t* debugstream) {
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
            constexpr char constexpr_pubkey_len[] = "public key len";
            constexpr char constexpr_pubkey[] = "public key";

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
                auto pkey_ske = keyexchange.find("SKE");
                crypto_kty_t kty = typeof_crypto_key(pkey_ske);
                nidof_evp_pkey(pkey_ske, nid);
                if (nid) {
                    if (kty_ec == kty || kty_okp == kty) {
                        ret = keychain.add_ec(&keyexchange, nid, pubkey, binary_t(), binary_t(), keydesc("CKE"));
                    }
                } else {
                    ret = errorcode_t::not_supported;
                }
            }

            if (debugstream) {
                debugstream->autoindent(1);
                debugstream->printf(" > %s %i\n", constexpr_pubkey_len, pubkey_len);
                debugstream->printf(" > %s\n", constexpr_pubkey);
                dump_memory(pubkey, debugstream, 16, 3, 0x0, dump_notrunc);
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
