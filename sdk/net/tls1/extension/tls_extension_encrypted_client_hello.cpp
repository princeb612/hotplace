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
#include <sdk/io/basic/payload.hpp>
#include <sdk/net/tls1/tls.hpp>
#include <sdk/net/tls1/tls_advisor.hpp>
#include <sdk/net/tls1/tls_extension.hpp>

namespace hotplace {
namespace net {

constexpr char constexpr_client_hello_type[] = "client hello type";
constexpr char constexpr_kdf[] = "kdf";
constexpr char constexpr_aead[] = "aead";
constexpr char constexpr_config_id[] = "config id";
constexpr char constexpr_enc_len[] = "enc len";
constexpr char constexpr_enc[] = "enc";
constexpr char constexpr_payload_len[] = "payload len";
constexpr char constexpr_payload[] = "payload";

tls_extension_encrypted_client_hello::tls_extension_encrypted_client_hello(tls_session* session)
    : tls_extension(tls1_ext_encrypted_client_hello, session), _client_hello_type(0), _kdf(0), _aead(0), _config_id(0), _enc_len(0), _enc_payload_len(0) {}

return_t tls_extension_encrypted_client_hello::read(const byte_t* stream, size_t size, size_t& pos) {
    return_t ret = errorcode_t::success;
    __try2 {
        ret = tls_extension::read(stream, size, pos);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        uint8 client_hello_type = 0;
        uint16 kdf = 0;
        uint16 aead = 0;
        uint8 config_id = 0;
        uint16 enc_len = 0;
        binary_t enc;
        uint16 enc_payload_len = 0;
        binary_t enc_payload;

        {
            payload pl;
            pl << new payload_member(uint8(0), constexpr_client_hello_type) << new payload_member(uint16(0), true, constexpr_kdf)
               << new payload_member(uint16(0), true, constexpr_aead) << new payload_member(uint8(0), constexpr_config_id)
               << new payload_member(uint16(0), true, constexpr_enc_len) << new payload_member(binary_t(), constexpr_enc)
               << new payload_member(uint16(0), true, constexpr_payload_len) << new payload_member(binary_t(), constexpr_payload);
            pl.set_reference_value(constexpr_enc, constexpr_enc_len);
            pl.set_reference_value(constexpr_payload, constexpr_payload_len);
            pl.read(stream, endpos_extension(), pos);

            client_hello_type = pl.t_value_of<uint8>(constexpr_client_hello_type);
            kdf = pl.t_value_of<uint16>(constexpr_kdf);
            aead = pl.t_value_of<uint16>(constexpr_aead);
            config_id = pl.t_value_of<uint8>(constexpr_config_id);
            enc_len = pl.t_value_of<uint16>(constexpr_enc_len);
            pl.get_binary(constexpr_enc, enc);
            enc_payload_len = pl.t_value_of<uint16>(constexpr_payload_len);
            pl.get_binary(constexpr_payload, enc_payload);
        }

        {
            _client_hello_type = client_hello_type;
            _kdf = kdf;
            _aead = aead;
            _config_id = config_id;
            _enc_len = enc_len;
            _enc = std::move(enc);
            _enc_payload_len = enc_payload_len;
            _enc_payload = std::move(enc_payload);
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_extension_encrypted_client_hello::write(binary_t& bin) { return not_supported; }

return_t tls_extension_encrypted_client_hello::dump(const byte_t* stream, size_t size, stream_t* s) {
    return_t ret = errorcode_t::success;
    __try2 {
        ret = tls_extension::dump(stream, size, s);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        {
            tls_advisor* tlsadvisor = tls_advisor::get_instance();
            uint8 client_hello_type = _client_hello_type;
            uint16 kdf = _kdf;
            uint16 aead = _aead;
            uint8 config_id = _config_id;
            uint16 enc_len = _enc_len;
            const binary_t& enc = _enc;
            uint16 enc_payload_len = _enc_payload_len;
            const binary_t& enc_payload = _enc_payload;

            s->printf(" > %s %i\n", constexpr_client_hello_type, client_hello_type);
            s->printf(" > %s %i %s\n", constexpr_kdf, kdf, tlsadvisor->kdf_id_string(kdf).c_str());
            s->printf(" > %s %i %s\n", constexpr_aead, aead, tlsadvisor->aead_alg_string(aead).c_str());
            s->printf(" > %s %i\n", constexpr_config_id, config_id);
            s->printf(" > %s %i\n", constexpr_enc_len, enc_len);
            dump_memory(enc, s, 16, 3, 0x0, dump_notrunc);
            s->printf(" > %s %i\n", constexpr_payload_len, enc_payload_len);
            dump_memory(enc_payload, s, 16, 3, 0x0, dump_notrunc);
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

}  // namespace net
}  // namespace hotplace
