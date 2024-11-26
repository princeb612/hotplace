/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/net/tlsspec/tlsspec.hpp>

namespace hotplace {
namespace net {

tls_session::tls_session() : _seq(0) {}

tls_protection& tls_session::get_tls_protection() { return _tls_protection; }

uint64 tls_session::get_sequence(bool inc) {
    uint64 value = inc ? _seq++ : _seq;
    _seq;
    return value;
}

void tls_session::inc_sequence() { _seq++; }

void tls_session::set(session_item_t type, const byte_t* begin, size_t size) {
    if (begin) {
        binary_t bin;
        bin.insert(bin.end(), begin, begin + size);
        _kv[type] = std::move(bin);
    }
}

void tls_session::set(session_item_t type, const binary_t& item) { _kv[type] = item; }

const binary_t& tls_session::get(session_item_t type) { return _kv[type]; }

void tls_session::erase(session_item_t type) {
    auto iter = _kv.find(type);
    if (_kv.end() != iter) {
        auto& bin = iter->second;
        memset(&bin[0], 0, bin.size());
        _kv.erase(iter);
    }
}

}  // namespace net
}  // namespace hotplace
