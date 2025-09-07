/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/net/tls/tls/extension/tls_extension_builder.hpp>
#include <sdk/net/tls/tls/extension/tls_extensions.hpp>

namespace hotplace {
namespace net {

tls_extensions::tls_extensions() {}

return_t tls_extensions::read(tls_handshake* handshake, tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos) {
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

        tls_extension_builder builder;
        while (pos < size) {
            if (pos + 4 > size) {
                ret = errorcode_t::no_more;
                break;
            }

            auto extension_type = ntoh16(*(uint16*)(stream + pos));
            auto extension = builder.set(handshake).set(dir).set(extension_type).build();
            if (extension) {
                ret = extension->read(dir, stream, size, pos);
                if (errorcode_t::success == ret) {
                    add(extension);
                } else {
                    extension->release();
                }
            }
        }
    }
    __finally2 {}
    return ret;
}

return_t tls_extensions::read(tls_handshake* handshake, tls_direction_t dir, const binary_t& bin) {
    const byte_t* stream = &bin[0];
    size_t size = bin.size();
    size_t pos = 0;
    return read(handshake, dir, stream, size, pos);
}

return_t tls_extensions::write(tls_direction_t dir, binary_t& bin) {
    return_t ret = errorcode_t::success;
    auto lambda = [&](tls_extension* extension) -> return_t { return extension->write(dir, bin); };
    ret = for_each(lambda);
    return ret;
}

return_t tls_extensions::add(tls_extension* extension, bool upref) { return _extensions.add(extension, upref); }

tls_extensions& tls_extensions::add(uint16 type, tls_direction_t dir, tls_handshake* handshake, std::function<return_t(tls_extension*)> func, bool upref) {
    __try2 {
        tls_extension_builder builder;
        auto extension = builder.set(type).set(dir).set(handshake).build();
        if (extension) {
            if (func) {
                auto test = func(extension);
                if (errorcode_t::success != test) {
                    extension->release();
                    __leave2;
                }
            }
            _extensions.add(extension, upref);
        }
    }
    __finally2 {}
    return *this;
}

tls_extensions& tls_extensions::operator<<(tls_extension* extension) {
    add(extension);
    return *this;
}

tls_extensions& tls_extensions::operator<<(tls_extensions* extensions) {
    if (extensions) {
        auto lambda = [&](tls_extension* ext) -> return_t { return add(ext, true); };

        critical_section_guard guard(_lock);
        extensions->for_each(lambda);
    }
    return *this;
}

return_t tls_extensions::for_each(std::function<return_t(tls_extension*)> func) { return _extensions.for_each(func); }

tls_extension* tls_extensions::get(uint16 type, bool upref) { return _extensions.get(type, upref); }

tls_extension* tls_extensions::getat(size_t index, bool upref) { return _extensions.getat(index, upref); }

bool tls_extensions::empty() { return _extensions.empty(); }

size_t tls_extensions::size() { return _extensions.size(); }

void tls_extensions::clear() { _extensions.clear(); }

}  // namespace net
}  // namespace hotplace
