/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/base/basic/dump_memory.hpp>
#include <hotplace/sdk/base/stream/basic_stream.hpp>
#include <hotplace/sdk/base/unittest/trace.hpp>
#include <hotplace/sdk/io/basic/payload.hpp>
#include <hotplace/sdk/net/tls/quic/quic.hpp>
#include <hotplace/sdk/net/tls/quic/quic_encoded.hpp>
#include <hotplace/sdk/net/tls/tls/extension/tls_extension_quic_transport_parameters.hpp>
#include <hotplace/sdk/net/tls/tls/handshake/tls_handshake.hpp>
#include <hotplace/sdk/net/tls/tls/tls.hpp>
#include <hotplace/sdk/net/tls/tls_advisor.hpp>
#include <hotplace/sdk/net/tls/tls_session.hpp>

namespace hotplace {
namespace net {

constexpr char constexpr_param_id[] = "param id";
constexpr char constexpr_param[] = "param";

tls_extension_quic_transport_parameters::tls_extension_quic_transport_parameters(tls_handshake* handshake)
    : tls_extension(tls_ext_quic_transport_parameters, handshake) {}

tls_extension_quic_transport_parameters::~tls_extension_quic_transport_parameters() {}

return_t tls_extension_quic_transport_parameters::do_read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos) {
    return_t ret = errorcode_t::success;
    __try2 {
        critical_section_guard guard(_lock);

        _params.clear();

        auto tpos = offsetof_header();
        auto ext_len = get_body_size();

        // RFC 9001 8.2.  QUIC Transport Parameters Extension
        // RFC 9000 18.  Transport Parameter Encoding
        ret = read_quic_params(stream, endpos_extension(), pos, _params);
    }
    __finally2 {}
    return ret;
}

return_t tls_extension_quic_transport_parameters::do_write_body(tls_direction_t dir, binary_t& bin) {
    return_t ret = errorcode_t::success;
    critical_section_guard guard(_lock);
    for (auto item : _params) {
        write_quic_param(item.first, item.second, bin);
    }
    return ret;
}

tls_extension_quic_transport_parameters& tls_extension_quic_transport_parameters::set(uint64 id, uint64 value) {
    critical_section_guard guard(_lock);
    switch (id) {
        case quic_param_original_destination_connection_id:
        case quic_param_stateless_reset_token:
        case quic_param_disable_active_migration:
        case quic_param_initial_source_connection_id:
        case quic_param_retry_source_connection_id:
        case 17:                   // version_information
        case 18258:                // google_version
        case 2792906686339107538:  // undocumented
        {
            _params.push_back({id, variant()});
        } break;
        default: {
            _params.push_back({id, variant(value)});
        } break;
    }
    return *this;
}

tls_extension_quic_transport_parameters& tls_extension_quic_transport_parameters::set(uint64 id, const binary_t& value) {
    critical_section_guard guard(_lock);
    switch (id) {
        case quic_param_disable_active_migration: {
            _params.push_back({id, variant()});
        } break;
        case quic_param_original_destination_connection_id:
        case quic_param_stateless_reset_token:
        case quic_param_initial_source_connection_id:
        case quic_param_retry_source_connection_id:
        case 17:                   // version_information
        case 18258:                // google_version
        case 2792906686339107538:  // undocumented
        {
            _params.push_back({id, variant(value)});
        } break;
        default: {
            _params.push_back({id, variant(uint64(0))});
        } break;
    }
    return *this;
}

return_t tls_extension_quic_transport_parameters::read_quic_params(const byte_t* stream, size_t size, size_t& pos,
                                                                   std::list<std::pair<uint64, variant>>& params) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        while (pos < size) {
            payload pl;
            pl << new payload_member(new quic_encoded(uint64(0)), constexpr_param_id)  //
               << new payload_member(new quic_encoded(binary_t()), constexpr_param);   //
            pl.read(stream, size, pos);

            uint64 param_id = pl.t_value_of<uint64>(constexpr_param_id);
            binary_t param;
            pl.get_binary(constexpr_param, param);

            switch (param_id) {
                case quic_param_original_destination_connection_id:
                case quic_param_stateless_reset_token:
                case quic_param_disable_active_migration:
                case quic_param_initial_source_connection_id:
                case quic_param_retry_source_connection_id:
                case 17:                   // version_information
                case 18258:                // google_version
                case 2792906686339107538:  // undocumented
                {
                    variant vt(param);
                    params.push_back({param_id, std::move(vt)});
                } break;
                default: {
                    size_t epos = 0;
                    uint64 value = 0;
                    quic_read_vle_int(param.empty() ? nullptr : &param[0], param.size(), epos, value);

                    variant vt(value);
                    params.push_back({param_id, std::move(vt)});
                } break;
            }
        }

#if defined DEBUG
        if (istraceable(trace_category_net)) {
            basic_stream dbs;
            tls_advisor* tlsadvisor = tls_advisor::get_instance();
            for (auto item : params) {
                auto param_id = item.first;
                const auto& v = item.second.content();

                dbs.printf("    > %I64i (%s) ", param_id, tlsadvisor->quic_param_string(param_id).c_str());
                switch (v.type) {
                    case TYPE_NULL: {
                    } break;
                    case TYPE_UINT64: {
                        dbs.printf("0x%I64x (%I64i)", v.data.ui64, v.data.ui64);
                    } break;
                    case TYPE_BINARY: {
                        vtprintf(&dbs, item.second, vtprintf_style_base16);
                    } break;
                }
                dbs.println("");
            }

            trace_debug_event(trace_category_net, trace_event_tls_extension, &dbs);
        }
#endif
    }
    __finally2 {}
    return ret;
}

return_t tls_extension_quic_transport_parameters::write_quic_param(uint64 id, const variant& value, binary_t& params) {
    return_t ret = errorcode_t::success;
    payload pl;
    switch (value.content().type) {
        case TYPE_NULL: {
            pl << new payload_member(new quic_encoded(id), constexpr_param_id)  //
               << new payload_member(new quic_encoded(uint64(0)), constexpr_param);
        } break;
        case TYPE_UINT64: {
            binary_t temp;
            quic_write_vle_int(value.content().data.ui64, temp);
            pl << new payload_member(new quic_encoded(id), constexpr_param_id)  //
               << new payload_member(new quic_encoded(temp), constexpr_param);
        } break;
        case TYPE_BINARY: {
            pl << new payload_member(new quic_encoded(id), constexpr_param_id)  //
               << new payload_member(new quic_encoded(value.to_bin()), constexpr_param);
        } break;
    }
    pl.write(params);
    return ret;
}

}  // namespace net
}  // namespace hotplace
