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

#include <hotplace/sdk/base/basic/dump_memory.hpp>
#include <hotplace/sdk/base/nostd/exception.hpp>
#include <hotplace/sdk/base/unittest/trace.hpp>
#include <hotplace/sdk/io/basic/payload.hpp>
#include <hotplace/sdk/net/tls/tls/extension/tls_extension.hpp>
#include <hotplace/sdk/net/tls/tls/extension/tls_extension_builder.hpp>
#include <hotplace/sdk/net/tls/tls/handshake/tls_handshake.hpp>
#include <hotplace/sdk/net/tls/tls/tls.hpp>
#include <hotplace/sdk/net/tls/tls_advisor.hpp>
#include <hotplace/sdk/net/tls/tls_session.hpp>

namespace hotplace {
namespace net {

constexpr char constexpr_extension[] = "extension";
constexpr char constexpr_ext_len[] = "extension len";
constexpr char constexpr_extension_type[] = "extension type";

tls_extension::tls_extension(tls_handshake* hs) : _hs(hs), _type(0), _bodysize(0), _size(0) {
    if (nullptr == hs) {
        throw exception(errorcode_t::no_session);
    }
    _shared.make_share(this);
}

tls_extension::tls_extension(const tls_extension& rhs) : _hs(rhs._hs), _type(rhs._type), _bodysize(rhs._bodysize), _size(rhs._size) {
    auto hs = get_handshake();
    if (nullptr == hs) {
        throw exception(errorcode_t::no_session);
    }
    _shared.make_share(this);
}

tls_extension::tls_extension(uint16 type, tls_handshake* hs) : _hs(hs), _type(type), _bodysize(0), _size(0) {
    if (nullptr == hs) {
        throw exception(errorcode_t::no_session);
    }
    _shared.make_share(this);
}

tls_extension::~tls_extension() {}

tls_extension* tls_extension::read(tls_handshake* handshake, tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos) {
    tls_extension* obj = nullptr;
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == handshake || nullptr == stream) {
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
            auto extension_type = ntoh16(*(uint16*)(stream + pos));
            tls_extension_builder builder;
            auto extension = builder.set(handshake).set(dir).set(extension_type).build();
            if (extension) {
                ret = extension->read(dir, stream, size, pos);
                if (errorcode_t::success == ret) {
                    obj = extension;
                } else {
                    extension->release();
                }
            }
        }
    }
    __finally2 {}
    return obj;
}

return_t tls_extension::read(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        ret = do_preprocess(dir);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        ret = do_read_header(dir, stream, size, pos);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        size_t tpos = pos;  // responding to unhandled extentions
        ret = do_read_body(dir, stream, size, tpos);
        pos += get_body_size();  // responding to unhandled extentions

        ret = do_postprocess(dir);
        if (errorcode_t::success != ret) {
            __leave2;
        }
    }
    __finally2 {}
    return ret;
}

return_t tls_extension::write(tls_direction_t dir, binary_t& bin) {
    return_t ret = errorcode_t::success;

    __try2 {
        ret = do_preprocess(dir);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        binary_t body;
        ret = do_write_body(dir, body);
        if (errorcode_t::success != ret) {
            __leave2;
        }
        ret = do_write_header(dir, bin, body);

        ret = do_preprocess(dir);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        ret = do_postprocess(dir);
        if (errorcode_t::success != ret) {
            __leave2;
        }
    }
    __finally2 {}
    return ret;
}

return_t tls_extension::do_preprocess(tls_direction_t dir) { return errorcode_t::success; }

return_t tls_extension::do_postprocess(tls_direction_t dir) { return errorcode_t::success; }

return_t tls_extension::do_read_header(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos) {
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
            pl << new payload_member(uint16(0), true, constexpr_extension_type)  //
               << new payload_member(uint16(0), true, constexpr_ext_len);
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

#if defined DEBUG
        if (istraceable(trace_category_net)) {
            trace_debug_event(trace_category_net, trace_event_tls_extension, [&](basic_stream& dbs) -> void {
                tls_advisor* tlsadvisor = tls_advisor::get_instance();

                dbs.println("  > %s - %04x %s", constexpr_extension, extension_type, tlsadvisor->nameof_tls_extension(extension_type).c_str());
                if (check_trace_level(loglevel_debug)) {
                    dump_memory(stream + offsetof_header(), get_extsize(), &dbs, 16, 4, 0x0, dump_notrunc);
                }
                dbs.println("   > %s 0x%04x(%i)", constexpr_ext_len, ext_len, ext_len);
            });
        }
#endif
    }
    __finally2 {}
    return ret;
}

return_t tls_extension::do_read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos) { return errorcode_t::not_supported; }

return_t tls_extension::do_write_header(tls_direction_t dir, binary_t& bin, const binary_t& body) {
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
        pl << new payload_member(uint16(get_type()), true, constexpr_extension_type)  //
           << new payload_member(uint16(_bodysize), true, constexpr_ext_len);
        pl.write(bin);
    }
    {
        // body
        bin.insert(bin.end(), body.begin(), body.end());
    }
    return ret;
}

return_t tls_extension::do_write_body(tls_direction_t dir, binary_t& bin) { return errorcode_t::not_supported; }

tls_handshake* tls_extension::get_handshake() { return _hs; }

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
