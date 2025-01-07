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
#include <sdk/net/tls1/tls.hpp>
#include <sdk/net/tls1/tls_advisor.hpp>
#include <sdk/net/tls1/tls_extension.hpp>

namespace hotplace {
namespace net {

constexpr char constexpr_len[] = "len";
constexpr char constexpr_formats[] = "formats";

tls_extension_ec_point_formats::tls_extension_ec_point_formats(tls_session* session) : tls_extension(tls1_ext_ec_point_formats, session) {}

return_t tls_extension_ec_point_formats::read_data(const byte_t* stream, size_t size, size_t& pos, stream_t* debugstream) {
    return_t ret = errorcode_t::success;
    __try2 {
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
        uint8 len = 0;

        {
            payload pl;
            pl << new payload_member(uint8(0), constexpr_len) << new payload_member(binary_t(0), constexpr_formats);
            pl.set_reference_value(constexpr_formats, constexpr_len);
            pl.read(stream, endpos_extension(), pos);

            len = pl.t_value_of<uint8>(constexpr_len);
            pl.get_binary(constexpr_formats, formats);
        }

        if (debugstream) {
            tls_advisor* tlsadvisor = tls_advisor::get_instance();

            debugstream->printf(" > %s %i\n", constexpr_formats, len);
            for (auto i = 0; i < len; i++) {
                auto fmt = formats[i];
                debugstream->printf("   [%i] 0x%02x(%i) %s\n", i, fmt, fmt, tlsadvisor->ec_point_format_string(fmt).c_str());
            }
        }

        {
            //
            _formats = std::move(formats);
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_extension_ec_point_formats::write(binary_t& bin, stream_t* debugstream) { return not_supported; }

tls_extension_ec_point_formats& tls_extension_ec_point_formats::add_format(uint8 fmt) {
    binary_append(_formats, fmt);
    return *this;
}

const binary_t& tls_extension_ec_point_formats::get_formats() { return _formats; }

}  // namespace net
}  // namespace hotplace
