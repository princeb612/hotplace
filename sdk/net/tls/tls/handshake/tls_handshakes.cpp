/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/net/tls/tls/handshake/tls_handshake_builder.hpp>
#include <sdk/net/tls/tls/handshake/tls_handshakes.hpp>
#include <sdk/net/tls/tls_session.hpp>

namespace hotplace {
namespace net {

tls_handshakes::tls_handshakes() : _dtls_seq(0) {}

return_t tls_handshakes::read(tls_session* session, tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == session || nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        // read
        while (pos < size) {
            if (size - pos < 4) {
                ret = errorcode_t::no_more;
                break;
            }

            tls_hs_type_t hs = (tls_hs_type_t)stream[pos];
            tls_handshake_builder builder;
            auto handshake = builder.set(hs).set(session).build();
            if (handshake) {
                auto test = handshake->read(dir, stream, size, pos);
                if (errorcode_t::success == test) {
                    add(handshake);
                } else if (errorcode_t::fragmented == test) {
                    handshake->release();
                    continue;
                } else {
                    handshake->release();
                    ret = test;
                    break;  // if error, no more preceed
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
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == session) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        const byte_t* stream = &bin[0];
        size_t size = bin.size();
        size_t pos = 0;
        auto ret = read(session, dir, stream, size, pos);
    }
    __finally2 {}
    return ret;
}

return_t tls_handshakes::write(tls_session* session, tls_direction_t dir, binary_t& bin) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == session) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        bool control_seq = false;
        if (session_type_dtls == session->get_type()) {
            control_seq = true;
        }

        auto lambda = [&](tls_handshake* handshake) -> return_t { return handshake->write(dir, bin); };
        ret = for_each(lambda);
    }
    __finally2 {}
    return ret;
}

return_t tls_handshakes::add(tls_handshake* handshake, bool upref) { return _handshakes.add(handshake, upref); }

tls_handshakes& tls_handshakes::operator<<(tls_handshake* handshake) {
    add(handshake);
    return *this;
}

return_t tls_handshakes::for_each(std::function<return_t(tls_handshake*)> func) { return _handshakes.for_each(func); }

tls_handshake* tls_handshakes::get(uint8 type, bool upref) { return _handshakes.get(type, upref); }

tls_handshake* tls_handshakes::getat(size_t index, bool upref) { return _handshakes.getat(index, upref); }

size_t tls_handshakes::size() { return _handshakes.size(); }

void tls_handshakes::clear() { _handshakes.clear(); }

void tls_handshakes::set_dtls_seq(uint16 seq) { _dtls_seq = seq; }

uint16 tls_handshakes::get_dtls_seq() { return _dtls_seq; }

}  // namespace net
}  // namespace hotplace
