/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <math.h>

#include <sdk/crypto/basic/openssl_kdf.hpp>
#include <sdk/net/quic/quic.hpp>

namespace hotplace {
namespace net {

quic_header_protection_keys::quic_header_protection_keys(const binary_t& salt, uint32 flags) {
    _shared.make_share(this);
    _kv[quic_original_dcid] = salt;
    compute(salt, binary_t(), flags);
}

quic_header_protection_keys::quic_header_protection_keys(const binary_t& salt, const binary_t& context, uint32 flags) {
    _shared.make_share(this);
    _kv[quic_original_dcid] = salt;
    compute(salt, context, flags);
}

const binary_t& quic_header_protection_keys::get_item(quic_initial_keys_t mode) { return _kv[mode]; }

void quic_header_protection_keys::get_item(quic_initial_keys_t mode, binary_t& item) { item = _kv[mode]; }

return_t quic_header_protection_keys::compute(const binary_t& salt, const binary_t& context, uint32 flags) {
    return_t ret = errorcode_t::success;
    openssl_kdf kdf;

    const char* initial_salt = "0x38762cf7f55934b34d179ae6a4c80cadccbb7f0a";
    binary_t bin_initial_salt = base16_decode_rfc(initial_salt);
    binary_t bin;
    binary_t bin_initial_secret;
    binary_t bin_client_initial_secret;
    binary_t bin_server_initial_secret;
    constexpr char alg[] = "sha256";

    /**
     * RFC 5869
     *  HKDF-Extract(salt, IKM) -> PRK
     *  HKDF-Expand(PRK, info, L) -> OKM
     *
     * RFC 9001 5.2.  Initial Secrets
     *  initial_salt = 0x38762cf7f55934b34d179ae6a4c80cadccbb7f0a
     *  quic_initial_secret = HKDF-Extract(initial_salt, client_dst_connection_id)
     *  client_initial_secret = HKDF-Expand-Label(quic_initial_secret, "client in", "", Hash.length)
     *  server_initial_secret = HKDF-Expand-Label(quic_initial_secret, "server in", "", Hash.length)
     */

    ret = kdf.hmac_kdf_extract(bin_initial_secret, alg, bin_initial_salt, salt);
    _kv[quic_initial_secret] = bin_initial_secret;

    if ((quic_client_secret | quic_client_key | quic_client_iv | quic_client_hp) & flags) {
        kdf.hkdf_expand_label(bin_client_initial_secret, alg, 32, bin_initial_secret, str2bin("client in"), context);
        _kv[quic_client_secret] = bin_client_initial_secret;

        if (quic_client_key & flags) {
            kdf.hkdf_expand_label(bin, alg, 16, bin_client_initial_secret, str2bin("quic key"), context);
            _kv[quic_client_key] = bin;
        }

        if (quic_client_iv & flags) {
            kdf.hkdf_expand_label(bin, alg, 12, bin_client_initial_secret, str2bin("quic iv"), context);
            _kv[quic_client_iv] = bin;
        }

        if (quic_client_hp & flags) {
            kdf.hkdf_expand_label(bin, alg, 16, bin_client_initial_secret, str2bin("quic hp"), context);
            _kv[quic_client_hp] = bin;
        }
    }

    if ((quic_server_secret | quic_server_key | quic_server_iv | quic_server_hp) & flags) {
        kdf.hkdf_expand_label(bin_server_initial_secret, alg, 32, bin_initial_secret, str2bin("server in"), context);
        _kv[quic_server_secret] = bin_server_initial_secret;

        if (quic_server_key & flags) {
            kdf.hkdf_expand_label(bin, alg, 16, bin_server_initial_secret, str2bin("quic key"), context);
            _kv[quic_server_key] = bin;
        }

        if (quic_server_iv & flags) {
            kdf.hkdf_expand_label(bin, alg, 12, bin_server_initial_secret, str2bin("quic iv"), context);
            _kv[quic_server_iv] = bin;
        }

        if (quic_server_hp & flags) {
            kdf.hkdf_expand_label(bin, alg, 16, bin_server_initial_secret, str2bin("quic hp"), context);
            _kv[quic_server_hp] = bin;
        }
    }

    return ret;
}

void quic_header_protection_keys::addref() { _shared.addref(); }

void quic_header_protection_keys::release() { _shared.delref(); }

}  // namespace net
}  // namespace hotplace
