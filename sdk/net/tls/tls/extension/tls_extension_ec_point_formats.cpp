/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   tls_extension_ec_point_formats.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/base/basic/function_pipeline.hpp>
#include <hotplace/sdk/base/stream/basic_stream.hpp>
#include <hotplace/sdk/base/system/trace.hpp>
#include <hotplace/sdk/io/basic/payload.hpp>
#include <hotplace/sdk/net/tls/tls/extension/tls_extension_ec_point_formats.hpp>
#include <hotplace/sdk/net/tls/tls/handshake/tls_handshake.hpp>
#include <hotplace/sdk/net/tls/tls/tls.hpp>
#include <hotplace/sdk/net/tls/tls_advisor.hpp>
#include <hotplace/sdk/net/tls/tls_session.hpp>

namespace hotplace {
namespace net {

constexpr char constexpr_len[] = "len";
constexpr char constexpr_formats[] = "formats";

tls_extension_ec_point_formats::tls_extension_ec_point_formats(tls_handshake* handshake) : tls_extension(tls_ext_ec_point_formats, handshake) {}

tls_extension_ec_point_formats::~tls_extension_ec_point_formats() {}

return_t tls_extension_ec_point_formats::do_postprocess(tls_direction_t dir) {
    return_t ret = errorcode_t::success;
    auto session = get_handshake()->get_session();
    auto& protection = session->get_tls_protection();
    auto& protection_context = protection.get_protection_context();
    for (auto epf : _ec_point_formats) {
        protection_context.add_ec_point_format(epf);
    }
    return ret;
}

return_t tls_extension_ec_point_formats::do_read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos) {
    function_pipeline<return_t> pipeline;

    pipeline  //
        .goahead_if_not_fail()
        .test_parameter([&]() -> bool { return (nullptr != stream); })
        .run_trycatch([&]() -> return_t {
            // RFC 8422 5.1.2.  Supported Point Formats Extension
            // enum {
            //     uncompressed (0),
            //     deprecated (1..2),
            //     reserved (248..255)
            // } ECPointFormat;
            // struct {
            //     ECPointFormat ec_point_format_list<1..2^8-1>
            // } ECPointFormatList;

            binary_t formats;
#if defined DEBUG
            uint8 len = 0;
#endif

            {
                payload pl;
                pl << new payload_member(uint8(0), constexpr_len)  //
                   << new payload_member(binary_t(0), constexpr_formats);
                pl.set_reference_value(constexpr_formats, constexpr_len);

                auto rc = pl.read(stream, endpos_extension(), pos);
                if (false == error_traits<return_t>::is_not_fail(rc)) {
                    __trace_return(rc);
                }

#if defined DEBUG
                len = pl.t_value_of<uint8>(constexpr_len);
#endif
                pl.get_binary(constexpr_formats, formats);
            }

            for (auto epf : formats) {
                add(epf);
            }

#if defined DEBUG
            if (istraceable(trace_category_net)) {
                trace_debug_event(trace_category_net, trace_event_tls_extension, [&](basic_stream& dbs) -> void {
                    tls_advisor* tlsadvisor = tls_advisor::get_instance();

                    dbs.println("   > %s (%i ent.)", constexpr_formats, len);
                    uint8 i = 0;
                    for (auto fmt : _ec_point_formats) {
                        dbs.println("     [%i] 0x%02x(%i) %s", i++, fmt, fmt, tlsadvisor->nameof_ec_point_format(fmt).c_str());
                    }
                });
            }
#endif
            return success;
        });
    return pipeline.result();
}

return_t tls_extension_ec_point_formats::do_write_body(tls_direction_t dir, binary_t& bin) {
    function_pipeline<return_t> pipeline;

    pipeline  //
        .run_trycatch([&]() -> return_t {
            uint8 cbsize_formats = 0;
            binary_t bin_formats;
            {
                for (auto epf : _ec_point_formats) {
                    // RFC 9325 4.2.1
                    // Note that [RFC8422] deprecates all but the uncompressed point format.
                    // Therefore, if the client sends an ec_point_formats extension, the ECPointFormatList MUST contain a single element, "uncompressed".
                    if (0 == epf) {
                        binary_append(bin_formats, epf);
                    }
                }
                cbsize_formats = t_narrow_cast(bin_formats.size());
            }

            payload pl;
            pl << new payload_member(uint8(cbsize_formats), constexpr_len)  //
               << new payload_member(bin_formats, constexpr_formats);

            return pl.write(bin);
        });
    return pipeline.result();
}

tls_extension_ec_point_formats& tls_extension_ec_point_formats::add(uint8 code) {
    _ec_point_formats.push_back(code);
    return *this;
}

tls_extension_ec_point_formats& tls_extension_ec_point_formats::add(const std::string& name) {
    tls_advisor* tlsadvisor = tls_advisor::get_instance();
    auto code = tlsadvisor->valueof_ec_point_format(name);
    return add(code);
}

void tls_extension_ec_point_formats::clear() { _ec_point_formats.clear(); }

}  // namespace net
}  // namespace hotplace
