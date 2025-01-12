/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/io/basic/payload.hpp>
#include <sdk/net/tls1/extension/tls_extension_psk_key_exchange_modes.hpp>
#include <sdk/net/tls1/tls.hpp>
#include <sdk/net/tls1/tls_advisor.hpp>
#include <sdk/net/tls1/tls_session.hpp>

namespace hotplace {
namespace net {

constexpr char constexpr_modes[] = "modes";
constexpr char constexpr_mode[] = "mode";

tls_extension_psk_key_exchange_modes::tls_extension_psk_key_exchange_modes(tls_session* session)
    : tls_extension(tls1_ext_psk_key_exchange_modes, session), _modes(0) {}

return_t tls_extension_psk_key_exchange_modes::do_read_body(const byte_t* stream, size_t size, size_t& pos, stream_t* debugstream) {
    return_t ret = errorcode_t::success;
    __try2 {
        // RFC 8446 4.2.9.  Pre-Shared Key Exchange Modes
        // enum { psk_ke(0), psk_dhe_ke(1), (255) } PskKeyExchangeMode;
        // struct {
        //     PskKeyExchangeMode ke_modes<1..255>;
        // } PskKeyExchangeModes;

        uint8 modes = 0;
        binary_t mode;
        {
            payload pl;
            pl << new payload_member(uint8(0), constexpr_modes) << new payload_member(binary_t(), constexpr_mode);
            pl.set_reference_value(constexpr_mode, constexpr_modes);
            pl.read(stream, endpos_extension(), pos);

            modes = pl.t_value_of<uint8>(constexpr_modes);
            pl.get_binary(constexpr_mode, mode);
        }

        if (debugstream) {
            tls_advisor* tlsadvisor = tls_advisor::get_instance();

            debugstream->printf(" > %s\n", constexpr_modes);
            for (auto i = 0; i < modes; i++) {
                auto m = mode[i];
                debugstream->printf("   [%i] %i %s\n", i, m, tlsadvisor->psk_key_exchange_mode_string(m).c_str());
            }
        }

        {
            _modes = modes;
            _mode = std::move(mode);
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_extension_psk_key_exchange_modes::write(binary_t& bin, stream_t* debugstream) { return errorcode_t::not_supported; }

}  // namespace net
}  // namespace hotplace
