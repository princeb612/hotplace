/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   binary_stream.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 */

#include <ctype.h>
#include <string.h>

#include <hotplace/sdk/base/stream/binary_stream.hpp>

namespace hotplace {

binary_stream::binary_stream() : _bigendian(true) {}

binary_stream::binary_stream(const binary_t& other) : _bigendian(true) { _bin = other; }

binary_stream::binary_stream(binary_t&& other) : _bigendian(true) { _bin = std::move(other); }

binary_stream& binary_stream::operator=(const binary_t& other) {
    _bin = other;
    return *this;
}

binary_stream& binary_stream::operator=(binary_t&& other) {
    _bin = std::move(other);
    return *this;
}

binary_stream& binary_stream::set_endian(bool bigendian) {
    _bigendian = bigendian;
    return *this;
}

const bool binary_stream::is_bigendian() const { return _bigendian; }

binary_stream& binary_stream::prefix(int8 value) {
    _bin.insert(_bin.begin(), (byte_t)value);
    return *this;
}

binary_stream& binary_stream::prefix(uint8 value) {
    _bin.insert(_bin.begin(), value);
    return *this;
}

binary_stream& binary_stream::prefix(int16 value) {
    binary_t temp;
    binary_append(temp, value, _bigendian ? hton16 : nullptr);
    _bin.insert(_bin.begin(), temp.begin(), temp.end());
    return *this;
}

binary_stream& binary_stream::prefix(uint16 value) {
    binary_t temp;
    binary_append(temp, value, _bigendian ? hton16 : nullptr);
    _bin.insert(_bin.begin(), temp.begin(), temp.end());
    return *this;
}

binary_stream& binary_stream::prefix(int32 value) {
    binary_t temp;
    binary_append(temp, value, _bigendian ? hton32 : nullptr);
    _bin.insert(_bin.begin(), temp.begin(), temp.end());
    return *this;
}

binary_stream& binary_stream::prefix(uint32 value) {
    binary_t temp;
    binary_append(temp, value, _bigendian ? hton32 : nullptr);
    _bin.insert(_bin.begin(), temp.begin(), temp.end());
    return *this;
}

binary_stream& binary_stream::prefix(int64 value) {
    binary_t temp;
    binary_append(temp, value, _bigendian ? hton64 : nullptr);
    _bin.insert(_bin.begin(), temp.begin(), temp.end());
    return *this;
}

binary_stream& binary_stream::prefix(uint64 value) {
    binary_t temp;
    binary_append(temp, value, _bigendian ? hton64 : nullptr);
    _bin.insert(_bin.begin(), temp.begin(), temp.end());
    return *this;
}

binary_stream& binary_stream::prefix(const binary_t& value) {
    _bin.insert(_bin.begin(), value.begin(), value.end());
    return *this;
}

binary_stream& binary_stream::append(int8 value) {
    _bin.push_back((byte_t)value);
    return *this;
}

binary_stream& binary_stream::append(uint8 value) {
    _bin.push_back(value);
    return *this;
}

binary_stream& binary_stream::append(int16 value) {
    binary_append(_bin, value, _bigendian ? hton16 : nullptr);
    return *this;
}

binary_stream& binary_stream::append(uint16 value) {
    binary_append(_bin, value, _bigendian ? hton16 : nullptr);
    return *this;
}

binary_stream& binary_stream::append(int32 value) {
    binary_append(_bin, value, _bigendian ? hton32 : nullptr);
    return *this;
}

binary_stream& binary_stream::append(uint32 value) {
    binary_append(_bin, value, _bigendian ? hton32 : nullptr);
    return *this;
}

binary_stream& binary_stream::append(int64 value) {
    binary_append(_bin, value, _bigendian ? hton64 : nullptr);
    return *this;
}

binary_stream& binary_stream::append(uint64 value) {
    binary_append(_bin, value, _bigendian ? hton64 : nullptr);
    return *this;
}

binary_stream& binary_stream::append(const byte_t* p, size_t len) {
    binary_append(_bin, p, len);
    return *this;
}

binary_stream& binary_stream::append(const std::string& value) {
    binary_append(_bin, value);
    return *this;
}

binary_stream& binary_stream::append(const binary_t& value) {
    binary_append(_bin, value);
    return *this;
}

void binary_stream::clear() { _bin.clear(); }

binary_t& binary_stream::get() { return _bin; }

const binary_t& binary_stream::get() const { return _bin; }

const size_t binary_stream::size() const { return _bin.size(); }

const bool binary_stream::empty() const { return _bin.empty(); }

}  // namespace hotplace
