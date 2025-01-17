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
#include <sdk/net/tls1/extension/tls_extension.hpp>
#include <sdk/net/tls1/extension/tls_extension_builder.hpp>
#include <sdk/net/tls1/tls.hpp>
#include <sdk/net/tls1/tls_advisor.hpp>
#include <sdk/net/tls1/tls_session.hpp>

namespace hotplace {
namespace net {

constexpr char constexpr_extension[] = "extension";
constexpr char constexpr_ext_len[] = "extension len";
constexpr char constexpr_extension_type[] = "extension type";

tls_extension::tls_extension(tls_session* session) : _session(session), _type(0), _bodysize(0), _size(0) {
    if (session) {
        session->addref();
    }
    _shared.make_share(this);
}

tls_extension::tls_extension(const tls_extension& rhs) : _session(rhs._session), _type(rhs._type), _bodysize(rhs._bodysize) {
    auto session = get_session();
    if (session) {
        _session->addref();
    }
    _shared.make_share(this);
}

tls_extension::tls_extension(uint16 type, tls_session* session) : _session(session), _type(type), _bodysize(0) {
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

tls_extension* tls_extension::read(tls_hs_type_t hstype, tls_session* session, tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos,
                                   stream_t* debugstream) {
    tls_extension* obj = nullptr;
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == session || nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        // extension
        //  uint16 type
        //  uint16 len
        //  ...
        if (pos + 4 > size) {
            ret = errorcode_t::no_more;
            __leave2;
        }

        {
            uint16 extension_type = ntoh16(*(uint16*)(stream + pos));
            tls_extension_builder builder;
            auto extension = builder.set(session).set(hstype).set(extension_type).build();
            if (extension) {
                ret = extension->read(stream, size, pos, debugstream);
                if (errorcode_t::success == ret) {
                    obj = extension;
                } else {
                    extension->release();
                }
            }
        }
    }
    __finally2 {
        // do nothing
    }
    return obj;
}

return_t tls_extension::read(const byte_t* stream, size_t size, size_t& pos, stream_t* debugstream) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        if (debugstream) {
            debugstream->autoindent(3);
        }

        __try2 {
            ret = do_read_header(stream, size, pos, debugstream);
            if (errorcode_t::success != ret) {
                __leave2;
            }

            size_t tpos = pos;  // responding to unhandled extentions
            ret = do_read_body(stream, size, tpos, debugstream);
            pos += get_body_size();  // responding to unhandled extentions
        }
        __finally2 {}

        if (debugstream) {
            debugstream->autoindent(0);
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_extension::do_read_header(const byte_t* stream, size_t size, size_t& pos, stream_t* debugstream) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        if (pos + 4 > size) {
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
            _bodysize = ext_len;
            _size = 4 + ext_len;  // pos - extpos + ext_len
        }

        if (debugstream) {
            tls_advisor* tlsadvisor = tls_advisor::get_instance();

            debugstream->printf("> %s - %04x %s\n", constexpr_extension, extension_type, tlsadvisor->tls_extension_string(extension_type).c_str());
            if (stream) {
                dump_memory(stream + offsetof_header(), get_extsize(), debugstream, 16, 3, 0x0, dump_notrunc);
            }
            debugstream->printf(" > %s 0x%04x(%i)\n", constexpr_ext_len, ext_len, ext_len);
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_extension::do_read_body(const byte_t* stream, size_t size, size_t& pos, stream_t* debugstream) { return errorcode_t::not_supported; }

return_t tls_extension::write(binary_t& bin, stream_t* debugstream) {
    return_t ret = errorcode_t::success;

    __try2 {
        binary_t body;
        ret = do_write_body(body);
        if (errorcode_t::success != ret) {
            __leave2;
        }
        ret = do_write_header(bin, body, debugstream);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_extension::do_write_header(binary_t& bin, const binary_t& body, stream_t* debugstream) {
    return_t ret = errorcode_t::success;
    {
        _header_range.begin = bin.size();
        _header_range.end = 4 + bin.size();
        _bodysize = body.size();
        _size = 4 + _bodysize;
    }
    {
        // header
        payload pl;
        pl << new payload_member(uint16(get_type()), true, constexpr_extension_type) << new payload_member(uint16(_bodysize), true, constexpr_ext_len);
        pl.write(bin);
    }
    {
        // body
        bin.insert(bin.end(), body.begin(), body.end());
    }
    return ret;
}

return_t tls_extension::do_write_body(binary_t& bin, stream_t* debugstream) { return errorcode_t::not_supported; }

tls_session* tls_extension::get_session() { return _session; }

void tls_extension::set_type(uint16 type) { _type = type; }

uint16 tls_extension::get_type() { return _type; }

const range_t& tls_extension::get_header_range() { return _header_range; }

size_t tls_extension::offsetof_header() { return _header_range.begin; }

size_t tls_extension::offsetof_body() { return _header_range.end; }

uint16 tls_extension::get_body_size() { return _bodysize; }

size_t tls_extension::get_extsize() { return _size; }

size_t tls_extension::endpos_extension() { return _header_range.end + _bodysize; }

void tls_extension::addref() { _shared.addref(); }

void tls_extension::release() { _shared.delref(); }

}  // namespace net
}  // namespace hotplace
