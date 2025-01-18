/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/net/tls1/handshake/tls_handshake_builder.hpp>
#include <sdk/net/tls1/handshake/tls_handshakes.hpp>

namespace hotplace {
namespace net {

tls_handshakes::tls_handshakes() {}

tls_handshakes::~tls_handshakes() { clear(); }

return_t tls_handshakes::read(tls_session* session, tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == session || nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        size_t pos = 0;
        while (pos < size) {
            if (size - pos < 4) {
                ret = errorcode_t::no_more;
                break;
            }

            tls_hs_type_t hs = (tls_hs_type_t)stream[pos];
            tls_handshake_builder builder;
            auto handshake = builder.set(hs).set(session).build();
            if (handshake) {
                ret = handshake->read(dir, stream, size, pos);
                if (errorcode_t::success == ret) {
                    add(handshake);
                } else {
                    handshake->release();
                }
            }
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_handshakes::read(tls_session* session, tls_direction_t dir, const binary_t& bin) {
    const byte_t* stream = &bin[0];
    size_t size = bin.size();
    size_t pos = 0;
    return read(session, dir, stream, size, pos);
}

return_t tls_handshakes::write(tls_session* session, tls_direction_t dir, binary_t& bin) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == session) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto lambda = [&](tls_handshake* handshake) -> void { handshake->write(dir, bin); };
        for_each(lambda);
    }
    __finally2 {}
    return ret;
}

return_t tls_handshakes::add(tls_handshake* handshake, bool upref) {
    return_t ret = errorcode_t::success;
    if (handshake) {
        if (upref) {
            handshake->addref();
        }

        critical_section_guard guard(_lock);

        auto type = handshake->get_type();
        auto iter = _dictionary.find(type);
        if (_dictionary.end() == iter) {
            _dictionary.insert({type, handshake});
            _handshakes.push_back(handshake);
        } else {
            handshake->release();
            ret = errorcode_t::already_exist;
        }
    }
    return ret;
}

tls_handshakes& tls_handshakes::operator<<(tls_handshake* handshake) {
    add(handshake);
    return *this;
}

void tls_handshakes::for_each(std::function<void(tls_handshake*)> func) {
    if (func) {
        critical_section_guard guard(_lock);
        for (auto item : _handshakes) {
            func(item);
        }
    }
}

tls_handshake* tls_handshakes::get(uint8 type, bool upref) {
    tls_handshake* obj = nullptr;
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

tls_handshake* tls_handshakes::getat(size_t index, bool upref) {
    tls_handshake* obj = nullptr;
    critical_section_guard guard(_lock);
    if (index < _handshakes.size()) {
        obj = _handshakes[index];
    }
    return obj;
}

size_t tls_handshakes::size() { return _handshakes.size(); }

void tls_handshakes::clear() {
    critical_section_guard guard(_lock);
    for (auto item : _handshakes) {
        item->release();
    }
    _handshakes.clear();
    _dictionary.clear();
}

}  // namespace net
}  // namespace hotplace
