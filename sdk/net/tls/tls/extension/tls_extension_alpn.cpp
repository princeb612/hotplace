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
#include <sdk/io/basic/payload.hpp>
#include <sdk/net/tls/tls/extension/tls_extension_alpn.hpp>
#include <sdk/net/tls/tls/tls.hpp>
#include <sdk/net/tls/tls_advisor.hpp>
#include <sdk/net/tls/tls_session.hpp>

namespace hotplace {
namespace net {

constexpr char constexpr_alpn_len[] = "alpn len";
constexpr char constexpr_protocol[] = "alpn protocol";

tls_extension_alpn::tls_extension_alpn(tls_handshake* handshake) : tls_extension(tls_ext_application_layer_protocol_negotiation, handshake) {}

return_t tls_extension_alpn::do_read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos) {
    return_t ret = errorcode_t::success;
    __try2 {
        auto session = get_handshake()->get_session();
        auto& protection = session->get_tls_protection();

        uint16 alpn_len = 0;
        binary_t protocols;
        {
            // RFC 7301

            payload pl;
            pl << new payload_member(uint16(0), true, constexpr_alpn_len) << new payload_member(binary_t(0), constexpr_protocol);
            pl.set_reference_value(constexpr_protocol, constexpr_alpn_len);
            pl.read(stream, endpos_extension(), pos);

            alpn_len = pl.t_value_of<uint16>(constexpr_alpn_len);
            pl.get_binary(constexpr_protocol, protocols);
        }

        {
            auto tlsadvisor = tls_advisor::get_instance();
            tlsadvisor->negotiate_alpn(get_handshake(), &protocols[0], protocols.size());
        }

#if defined DEBUG
        if (istraceable(trace_category_net)) {
            basic_stream dbs;
            dbs.println("   > %s %i", constexpr_alpn_len, alpn_len);
            dump_memory(protocols, &dbs, 16, 5, 0x0, dump_notrunc);

            trace_debug_event(trace_category_net, trace_event_tls_extension, &dbs);
        }
#endif

        {
            //
            _protocols = std::move(protocols);
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_extension_alpn::do_write_body(tls_direction_t dir, binary_t& bin) {
    return_t ret = errorcode_t::success;
    {
        payload pl;
        pl << new payload_member(uint16(_protocols.size()), true, constexpr_alpn_len)  //
           << new payload_member(_protocols, constexpr_protocol);                      //
        pl.write(bin);
    }
    return ret;
}

const binary_t& tls_extension_alpn::get_protocols() { return _protocols; }

void tls_extension_alpn::set_protocols(const binary_t& protocols) { _protocols = protocols; }

}  // namespace net
}  // namespace hotplace
