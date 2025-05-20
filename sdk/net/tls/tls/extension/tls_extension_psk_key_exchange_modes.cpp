/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/base/stream/basic_stream.hpp>
#include <sdk/base/unittest/trace.hpp>
#include <sdk/io/basic/payload.hpp>
#include <sdk/net/tls/tls/extension/tls_extension_psk_key_exchange_modes.hpp>
#include <sdk/net/tls/tls/tls.hpp>
#include <sdk/net/tls/tls_advisor.hpp>
#include <sdk/net/tls/tls_session.hpp>

namespace hotplace {
namespace net {

constexpr char constexpr_modes[] = "modes";
constexpr char constexpr_mode[] = "mode";

tls_extension_psk_key_exchange_modes::tls_extension_psk_key_exchange_modes(tls_session* session)
    : tls_extension(tls_ext_psk_key_exchange_modes, session), _modes(0) {}

return_t tls_extension_psk_key_exchange_modes::do_read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos) {
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

            for (auto i = 0; i < modes; i++) {
                auto m = mode[i];
                add(m);
            }
        }

#if defined DEBUG
        if (istraceable()) {
            basic_stream dbs;
            tls_advisor* tlsadvisor = tls_advisor::get_instance();

            dbs.println("   > %s", constexpr_modes);
            int i = 0;
            for (auto m : _modes) {
                dbs.println("     [%i] %i %s", i++, m, tlsadvisor->psk_key_exchange_mode_name(m).c_str());
            }
            trace_debug_event(trace_category_net, trace_event_tls_extension, &dbs);
        }
#endif
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_extension_psk_key_exchange_modes::do_write_body(tls_direction_t dir, binary_t& bin) {
    return_t ret = errorcode_t::success;
    uint8 cbsize_modes = 0;
    binary_t bin_modes;
    {
        for (auto m : _modes) {
            binary_append(bin_modes, m);
        }
        cbsize_modes = bin_modes.size();
    }
    {
        payload pl;
        pl << new payload_member(cbsize_modes, constexpr_modes) << new payload_member(bin_modes, constexpr_mode);
        pl.write(bin);
    }
    return ret;
}

tls_extension_psk_key_exchange_modes& tls_extension_psk_key_exchange_modes::add(uint8 code) {
    _modes.push_back(code);
    return *this;
}

tls_extension_psk_key_exchange_modes& tls_extension_psk_key_exchange_modes::add(const std::string& name) {
    tls_advisor* tlsadvisor = tls_advisor::get_instance();
    auto code = tlsadvisor->psk_key_exchange_mode_code(name);
    return add(code);
}

}  // namespace net
}  // namespace hotplace
