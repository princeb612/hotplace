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
#include <sdk/net/quic/quic.hpp>
#include <sdk/net/tls1/tls.hpp>
#include <sdk/net/tls1/tls_advisor.hpp>
#include <sdk/net/tls1/tls_extension.hpp>

namespace hotplace {
namespace net {

constexpr char constexpr_param_id[] = "param id";
constexpr char constexpr_param[] = "param";

tls_extension_quic_transport_parameters::tls_extension_quic_transport_parameters(tls_session* session)
    : tls_extension(tls1_ext_quic_transport_parameters, session) {}

return_t tls_extension_quic_transport_parameters::read(const byte_t* stream, size_t size, size_t& pos) {
    return_t ret = errorcode_t::success;
    __try2 {
        ret = tls_extension::read(stream, size, pos);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        auto tpos = get_header_range().begin;
        auto ext_len = get_length();

        // RFC 9001 8.2.  QUIC Transport Parameters Extension
        // RFC 9000 18.  Transport Parameter Encoding
        while (pos < tpos + ext_len) {
            payload pl;
            pl << new payload_member(new quic_encoded(uint64(0)), constexpr_param_id) << new payload_member(new quic_encoded(binary_t()), constexpr_param);
            pl.read(stream, endpos_extension(), pos);

            binary_t param;
            uint64 param_id = pl.select(constexpr_param_id)->get_payload_encoded()->value();
            pl.select(constexpr_param)->get_payload_encoded()->get_variant().to_binary(param);

            _keys.push_back(param_id);
            _params.insert({param_id, std::move(param)});
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_extension_quic_transport_parameters::write(binary_t& bin) { return errorcode_t::not_supported; }

return_t tls_extension_quic_transport_parameters::dump(const byte_t* stream, size_t size, stream_t* s) {
    return_t ret = errorcode_t::success;
    __try2 {
        ret = tls_extension::dump(stream, size, s);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        tls_advisor* tlsadvisor = tls_advisor::get_instance();
        for (auto item : _keys) {
            auto iter = _params.find(item);

            auto param_id = item;
            const binary_t& param = iter->second;

            switch (param_id) {
                case quic_param_initial_source_connection_id:
                case quic_param_retry_source_connection_id:
                    s->printf(" > %I64i (%s)\n", param_id, tlsadvisor->quic_param_string(param_id).c_str());
                    dump_memory(param, s, 16, 5, 0x0, dump_notrunc);
                    break;
                default: {
                    size_t epos = 0;
                    uint64 value = 0;
                    quic_read_vle_int(&param[0], param.size(), epos, value);
                    s->printf(" > %I64i (%s) %I64i\n", param_id, tlsadvisor->quic_param_string(param_id).c_str(), value);
                } break;
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
