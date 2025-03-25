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
#include <sdk/net/tls/quic/quic.hpp>
#include <sdk/net/tls/quic/quic_encoded.hpp>
#include <sdk/net/tls/tls/extension/tls_extension_quic_transport_parameters.hpp>
#include <sdk/net/tls/tls/tls.hpp>
#include <sdk/net/tls/tls_advisor.hpp>
#include <sdk/net/tls/tls_session.hpp>

namespace hotplace {
namespace net {

constexpr char constexpr_param_id[] = "param id";
constexpr char constexpr_param[] = "param";

tls_extension_quic_transport_parameters::tls_extension_quic_transport_parameters(tls_session* session)
    : tls_extension(tls1_ext_quic_transport_parameters, session) {}

return_t tls_extension_quic_transport_parameters::do_read_body(const byte_t* stream, size_t size, size_t& pos) {
    return_t ret = errorcode_t::success;
    __try2 {
        auto tpos = offsetof_header();
        auto ext_len = get_body_size();

        // RFC 9001 8.2.  QUIC Transport Parameters Extension
        // RFC 9000 18.  Transport Parameter Encoding
        while (pos < tpos + ext_len) {
            payload pl;
            pl << new payload_member(new quic_encoded(uint64(0)), constexpr_param_id) << new payload_member(new quic_encoded(binary_t()), constexpr_param);
            pl.read(stream, endpos_extension(), pos);

            binary_t param;
            uint64 param_id = pl.t_value_of<uint64>(constexpr_param_id);
            pl.get_binary(constexpr_param, param);

            _keys.push_back(param_id);
            _params.insert({param_id, std::move(param)});
        }

        if (istraceable()) {
            basic_stream dbs;
            tls_advisor* tlsadvisor = tls_advisor::get_instance();
            for (auto item : _keys) {
                auto iter = _params.find(item);

                auto param_id = item;
                const binary_t& param = iter->second;

                switch (param_id) {
                    case quic_param_original_destination_connection_id:
                    case quic_param_initial_source_connection_id:
                    case quic_param_retry_source_connection_id:
                        dbs.println("   > %I64i (%s) %s", param_id, tlsadvisor->quic_param_string(param_id).c_str(), base16_encode(param).c_str());
                        break;
                    default: {
                        size_t epos = 0;
                        uint64 value = 0;
                        quic_read_vle_int(&param[0], param.size(), epos, value);
                        dbs.println("   > %I64i (%s) %I64i", param_id, tlsadvisor->quic_param_string(param_id).c_str(), value);
                    } break;
                }
            }

            trace_debug_event(category_net, net_event_tls_read, &dbs);
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_extension_quic_transport_parameters::do_write_body(binary_t& bin) { return errorcode_t::not_supported; }

}  // namespace net
}  // namespace hotplace
