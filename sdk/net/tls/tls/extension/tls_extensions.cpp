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

tls_extensions::~tls_extensions() { clear(); }

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
    __finally2 {
        // do nothing
    }
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

return_t tls_extensions::add(tls_extension* extension, bool upref) {
    return_t ret = errorcode_t::success;
    if (extension) {
        if (upref) {
            extension->addref();
        }

        critical_section_guard guard(_lock);

        auto type = extension->get_type();
        auto iter = _dictionary.find(type);
        if (_dictionary.end() != iter) {
            auto older = iter->second;
            older->release();
            _dictionary.erase(iter);
        }
        _dictionary.insert({type, extension});
        _extensions.push_back(extension);
    }
    return ret;
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

return_t tls_extensions::for_each(std::function<return_t(tls_extension*)> func) {
    return_t ret = errorcode_t::success;
    if (func) {
        critical_section_guard guard(_lock);
        for (auto item : _extensions) {
            ret = func(item);
            if (errorcode_t::success != ret) {
                break;
            }
        }
    }
    return ret;
}

tls_extension* tls_extensions::get(uint16 type, bool upref) {
    tls_extension* obj = nullptr;
    critical_section_guard guard(_lock);
    auto iter = _dictionary.find(type);
    if (_dictionary.end() != iter) {
        obj = iter->second;
        if (upref) {
            obj->addref();
        }
    }
    return obj;
}

tls_extension* tls_extensions::getat(size_t index, bool upref) {
    tls_extension* obj = nullptr;
    critical_section_guard guard(_lock);
    if (index < _extensions.size()) {
        obj = _extensions[index];
    }
    return obj;
}

size_t tls_extensions::size() { return _extensions.size(); }

void tls_extensions::clear() {
    critical_section_guard guard(_lock);
    for (auto item : _extensions) {
        item->release();
    }
    _extensions.clear();
    _dictionary.clear();
}

}  // namespace net
}  // namespace hotplace
