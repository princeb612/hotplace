/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *          RFC 8446 The Transport Layer Security (TLS) Protocol Version 1.3
 *          RFC 6066 Transport Layer Security (TLS) Extensions: Extension Definitions
 *          RFC 5246 The Transport Layer Security (TLS) Protocol Version 1.2
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

constexpr char constexpr_extension[] = "extension";
constexpr char constexpr_ext_len[] = "extension len";
constexpr char constexpr_extension_type[] = "extension type";

tls_extension::tls_extension(tls_session* session) : _session(session), _type(0), _payload_len(0), _size(0) {
    if (session) {
        session->addref();
    }
    _shared.make_share(this);
}

tls_extension::tls_extension(const tls_extension& rhs) : _session(rhs._session), _type(rhs._type), _payload_len(rhs._payload_len) {
    auto session = get_session();
    if (session) {
        _session->addref();
    }
    _shared.make_share(this);
}

tls_extension::tls_extension(uint16 type, tls_session* session) : _session(session), _type(type), _payload_len(0) {
    if (session) {
        _session->addref();
    }
    _shared.make_share(this);
}

tls_extension::~tls_extension() {
    auto session = get_session();
    if (session) {
        session->release();
    }
}

return_t tls_extension::read(const byte_t* stream, size_t size, size_t& pos, stream_t* debugstream) {
    return_t ret = errorcode_t::success;
    __try2 {
        ret = read_header(stream, size, pos, debugstream);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        size_t tpos = pos;  // responding to unhandled extentions
        ret = read_data(stream, size, tpos, debugstream);
        pos += get_length();  // responding to unhandled extentions
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_extension::read_header(const byte_t* stream, size_t size, size_t& pos, stream_t* debugstream) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        if (pos + 4 >= size) {
            ret = errorcode_t::no_more;
            __leave2;
        }

        size_t extpos = pos;
        uint16 extension_type = 0;
        uint16 ext_len = 0;
        {
            payload pl;
            pl << new payload_member(uint16(0), true, constexpr_extension_type) << new payload_member(uint16(0), true, constexpr_ext_len);
            ret = pl.read(stream, size, pos);
            if (errorcode_t::success != ret) {
                __leave2;
            }

            extension_type = pl.t_value_of<uint16>(constexpr_extension_type);
            ext_len = pl.t_value_of<uint16>(constexpr_ext_len);
        }

        if (size - pos < ext_len) {
            ret = errorcode_t::no_more;
            __leave2;
        }

        {
            _header_range.begin = extpos;
            _header_range.end = pos;
            _type = extension_type;
            _payload_len = ext_len;
            _size = 4 + ext_len;  // pos - extpos + ext_len
        }

        if (debugstream) {
            tls_advisor* tlsadvisor = tls_advisor::get_instance();
            auto extension_type = get_type();
            auto ext_len = get_length();

            debugstream->printf("> %s - %04x %s\n", constexpr_extension, extension_type, tlsadvisor->tls_extension_string(extension_type).c_str());
            dump_memory(stream + get_header_range().begin, get_extsize(), debugstream, 16, 3, 0x0, dump_notrunc);
            debugstream->printf(" > %s 0x%04x(%i)\n", constexpr_ext_len, ext_len, ext_len);
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_extension::read_data(const byte_t* stream, size_t size, size_t& pos, stream_t* debugstream) { return errorcode_t::not_supported; }

return_t tls_extension::write(binary_t& bin, stream_t* debugstream) { return not_supported; }

tls_session* tls_extension::get_session() { return _session; }

void tls_extension::set_type(uint16 type) { _type = type; }

uint16 tls_extension::get_type() { return _type; }

const range_t& tls_extension::get_header_range() { return _header_range; }

uint16 tls_extension::get_length() { return _payload_len; }

size_t tls_extension::get_extsize() { return _size; }

size_t tls_extension::endpos_extension() { return _header_range.end + _payload_len; }

void tls_extension::addref() { _shared.addref(); }

void tls_extension::release() { _shared.delref(); }

}  // namespace net
}  // namespace hotplace
