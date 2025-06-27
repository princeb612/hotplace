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
#include <sdk/base/stream/basic_stream.hpp>
#include <sdk/base/unittest/trace.hpp>
#include <sdk/io/basic/payload.hpp>
#include <sdk/net/tls/tls/handshake/dtls_handshake_fragmented.hpp>
#include <sdk/net/tls/tls_advisor.hpp>
#include <sdk/net/tls/tls_protection.hpp>
#include <sdk/net/tls/tls_session.hpp>

namespace hotplace {
namespace net {

dtls_handshake_fragmented::dtls_handshake_fragmented(tls_hs_type_t type, tls_session* session) : tls_handshake(type, session) {
    set_flags(dont_control_dtls_handshake_sequence);
}

return_t dtls_handshake_fragmented::write(tls_direction_t dir, binary_t& bin) {
    return_t ret = errorcode_t::success;
    do_write_header(dir, bin, _fragmented);
#if defined DEBUG
    if (istraceable(trace_category_net, loglevel_debug)) {
        basic_stream dbs;
        tls_advisor* tlsadvisor = tls_advisor::get_instance();
        dbs.printf("\e[1;36m");
        dbs.println("# generate %s seq %i", tlsadvisor->handshake_type_string(get_type()).c_str(), get_dtls_seq());
        dbs.printf("\e[0m");
        if (check_trace_level(loglevel_debug)) {
            dump_memory(&bin[0], sizeof(dtls_handshake_t), &dbs, 16, 3, 0, dump_notrunc);
            dump_memory(_fragmented, &dbs, 16, 3, 0, dump_notrunc);
        } else {
            dump_memory(bin, &dbs, 16, 3, 0, dump_notrunc);
        }
        trace_debug_event(trace_category_net, trace_event_tls_handshake, &dbs);
    }
#endif
    return ret;
}

return_t dtls_handshake_fragmented::prepare_fragment(const byte_t* stream, uint32 size, uint16 seq, uint32 fragment_offset, uint32 fragment_length) {
    return_t ret = errorcode_t::success;
    __try2 {
        if ((0 != size) && (nullptr == stream)) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        ret = tls_handshake::prepare_fragment(stream, size, seq, fragment_offset, fragment_length);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        _fragmented.insert(_fragmented.end(), stream + fragment_offset, stream + fragment_offset + fragment_length);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

}  // namespace net
}  // namespace hotplace
