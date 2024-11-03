/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/net/quic/quic.hpp>

namespace hotplace {
namespace net {

quic_integer::quic_integer() : payload_encoded(), _datalink(true), _len(0) {}

quic_integer::quic_integer(const quic_integer& rhs) : payload_encoded(), _datalink(rhs._datalink), _len(rhs._len), _data(rhs._data) {}

quic_integer::quic_integer(quic_integer&& rhs) : payload_encoded(), _datalink(rhs._datalink), _len(rhs._len), _data(rhs._data) {}

quic_integer::quic_integer(uint64 data) : payload_encoded(), _datalink(false), _len(data) {}

quic_integer::quic_integer(const char* data) : payload_encoded(), _datalink(true) {
    if (data) {
        _len = strlen(data);
        _data.set_strn_new(data, _len);
    }
}

quic_integer::quic_integer(const std::string& data) : payload_encoded(), _datalink(true) {
    _len = data.size();
    _data.set_str_new(data);
}

quic_integer::quic_integer(const binary_t& data) : payload_encoded(), _datalink(true) {
    _len = data.size();
    _data.set_binary_new(data);
}

size_t quic_integer::lsize() {
    uint8 length = 0;
    quic_length_vle_int(_len, length);
    return length;
}

size_t quic_integer::value() { return _len; }

const byte_t* quic_integer::data() {
    const byte_t* p = nullptr;
    if (_datalink) {
        p = _data.content().data.bstr;
    }
    return p;
}

void quic_integer::write(binary_t& target) {
    quic_write_vle_int(_len, target);
    if (_datalink) {
        _data.to_binary(target);
    }
}

size_t quic_integer::lsize(const byte_t* stream, size_t size) {
    size_t pos = 0;
    uint64 value = 0;
    quic_read_vle_int(stream, size, pos, value);
    return pos;
}

size_t quic_integer::value(const byte_t* stream, size_t size) {
    size_t pos = 0;
    uint64 value = 0;
    quic_read_vle_int(stream, size, pos, value);
    return value;
}

void quic_integer::read(const byte_t* stream, size_t size, size_t& pos) {
    if (stream) {
        size_t old = pos;
        quic_read_vle_int(stream, size, pos, _len);
        if (_datalink) {
            _data.clear().set_bstr_new(stream + pos - old, _len);
            pos += _len;
        }
    }
}

}  // namespace net
}  // namespace hotplace
