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
#include <sdk/net/quic/quic_encoded.hpp>

namespace hotplace {
namespace net {

quic_encoded::quic_encoded() : payload_encoded(), _datalink(true), _value(0), _sizeof_value(0) {}

quic_encoded::quic_encoded(const quic_encoded& rhs)
    : payload_encoded(), _datalink(rhs._datalink), _value(rhs._value), _sizeof_value(rhs._sizeof_value), _data(rhs._data) {}

quic_encoded::quic_encoded(quic_encoded&& rhs)
    : payload_encoded(), _datalink(rhs._datalink), _value(rhs._value), _sizeof_value(rhs._sizeof_value), _data(rhs._data) {}

quic_encoded::quic_encoded(uint64 data) : payload_encoded(), _datalink(false), _value(data), _sizeof_value(0) {}

quic_encoded::quic_encoded(uint64 data, uint8 prefix) : payload_encoded(), _datalink(false), _value(data), _sizeof_value(0) {
    if (prefix < 5) {
        _sizeof_value = (prefix << 1);
    }
}

quic_encoded::quic_encoded(const char* data) : payload_encoded(), _datalink(true) {
    if (data) {
        _value = strlen(data);
        _data.set_strn_new(data, _value);
        quic_length_vle_int(_value, _sizeof_value);
    }
}

quic_encoded::quic_encoded(const std::string& data) : payload_encoded(), _datalink(true) {
    _value = data.size();
    _data.set_str_new(data);
    quic_length_vle_int(_value, _sizeof_value);
}

quic_encoded::quic_encoded(const binary_t& data) : payload_encoded(), _datalink(true) {
    _value = data.size();
    _data.set_binary_new(data);
    quic_length_vle_int(_value, _sizeof_value);
}

quic_encoded& quic_encoded::set(const char* data) {
    if (data) {
        _value = strlen(data);
        _data.clear().set_strn_new(data, _value);
        quic_length_vle_int(_value, _sizeof_value);
    }
    return *this;
}
quic_encoded& quic_encoded::set(const std::string& data) {
    _value = data.size();
    _data.clear().set_str_new(data);
    quic_length_vle_int(_value, _sizeof_value);
    return *this;
}
quic_encoded& quic_encoded::set(const binary_t& data) {
    _value = data.size();
    _data.clear().set_binary_new(data);
    quic_length_vle_int(_value, _sizeof_value);
    return *this;
}

size_t quic_encoded::lsize() {
    /* quic_length_vle_int is minimum size */
    size_t value = 0;
    if (_sizeof_value) {
        value = _sizeof_value;
    } else {
        uint8 length = 0;
        quic_length_vle_int(_value, length);
        value = length;
    }
    return value;
}

size_t quic_encoded::value() { return _value; }

const byte_t* quic_encoded::data() {
    const byte_t* p = nullptr;
    if (_datalink) {
        p = _data.content().data.bstr;
    }
    return p;
}

return_t quic_encoded::read(const byte_t* stream, size_t size, size_t& pos) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        size_t old = pos;
        ret = quic_read_vle_int(stream, size, pos, _value);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        if (_datalink) {
            _data.clear().set_bstr_new(stream + pos - old, _value);
            pos += _value;
            quic_length_vle_int(pos - old, _sizeof_value);
        } else {
            _sizeof_value = pos - old;
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

void quic_encoded::write(binary_t& target) {
    uint8 prefix = _sizeof_value >> 1;
    quic_write_vle_int(_value, prefix, target);
    if (_datalink) {
        _data.to_binary(target);
    }
}

size_t quic_encoded::lsize(const byte_t* stream, size_t size) {
    size_t pos = 0;
    uint64 value = 0;
    quic_read_vle_int(stream, size, pos, value);
    return pos;
}

size_t quic_encoded::value(const byte_t* stream, size_t size) {
    size_t pos = 0;
    uint64 value = 0;
    quic_read_vle_int(stream, size, pos, value);
    return value;
}

variant& quic_encoded::get_variant() { return _data; }

}  // namespace net
}  // namespace hotplace
