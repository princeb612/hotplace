/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/net/tls1/extension/tls_extension_builder.hpp>
#include <sdk/net/tls1/extension/tls_extensions.hpp>

namespace hotplace {
namespace net {

tls_extensions::tls_extensions() {}

tls_extensions::~tls_extensions() { clear(); }

return_t tls_extensions::read(tls_hs_type_t hstype, tls_session* session, tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos,
                              stream_t* debugstream) {
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

        while (pos < size) {
            if (pos + 4 > size) {
                ret = errorcode_t::no_more;
                break;
            }

            uint16 extension_type = ntoh16(*(uint16*)(stream + pos));
            tls_extension_builder builder;
            auto extension = builder.set(session).set(hstype).set(extension_type).build();
            if (extension) {
                ret = extension->read(stream, size, pos, debugstream);
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

return_t tls_extensions::read(tls_hs_type_t hstype, tls_session* session, tls_direction_t dir, const binary_t& bin, stream_t* debugstream) {
    const byte_t* stream = &bin[0];
    size_t size = bin.size();
    size_t pos = 0;
    return read(hstype, session, dir, stream, size, pos, debugstream);
}

return_t tls_extensions::write(binary_t& bin, stream_t* debugstream) {
    return_t ret = errorcode_t::success;
    for_each([&](tls_extension* extension) -> void { extension->write(bin, debugstream); });
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
        if (_dictionary.end() == iter) {
            _dictionary.insert({type, extension});
            _extensions.push_back(extension);
        } else {
            extension->release();
            ret = errorcode_t::already_exist;
        }
    }
    return ret;
}

tls_extensions& tls_extensions::operator<<(tls_extension* extension) {
    add(extension);
    return *this;
}

void tls_extensions::for_each(std::function<void(tls_extension*)> func) {
    if (func) {
        critical_section_guard guard(_lock);
        for (auto item : _extensions) {
            func(item);
        }
    }
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
