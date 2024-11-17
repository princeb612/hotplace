/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <stdarg.h>
#include <string.h>

#include <sdk/base/basic/binary.hpp>

namespace hotplace {

binary::binary() : _be(false) {}

binary::binary(const binary& rhs) : _be(false), _bin(rhs._bin) {}

binary::binary(binary&& rhs) : _be(false), _bin(std::move(rhs._bin)) {}

binary::binary(char rhs) : _be(false) { push_back(rhs); }

binary::binary(byte_t rhs) : _be(false) { push_back(rhs); }

binary::binary(int16 rhs) : _be(false) { append(rhs); }

binary::binary(uint16 rhs) : _be(false) { append(rhs); }

binary::binary(int32 rhs) : _be(false) { append(rhs); }

binary::binary(uint32 rhs) : _be(false) { append(rhs); }

binary::binary(int64 rhs) : _be(false) { append(rhs); }

binary::binary(uint64 rhs) : _be(false) { append(rhs); }

binary::binary(int128 rhs) : _be(false) { append(rhs); }

binary::binary(uint128 rhs) : _be(false) { append(rhs); }

binary::binary(float rhs) : _be(false) { append(rhs); }

binary::binary(double rhs) : _be(false) { append(rhs); }

binary::binary(const std::string& rhs) : _be(false) { append(rhs); }

binary::binary(const char* rhs) : _be(false) { append(rhs); }

binary::binary(const byte_t* buf, size_t size) : _be(false) { append(buf, size); }

binary::binary(const binary_t& rhs) : _be(false), _bin(rhs) {}

binary::binary(binary_t&& rhs) : _be(false), _bin(std::move(rhs)) {}

binary& binary::push_back(byte_t rhs) {
    binary_push(_bin, rhs);
    return *this;
}

binary& binary::append(int16 value, std::function<int16(int16)> func) {
    t_binary_append<int16>(_bin, value, func);
    return *this;
}

binary& binary::append(uint16 value, std::function<uint16(uint16)> func) {
    t_binary_append<uint16>(_bin, value, func);
    return *this;
}

binary& binary::append(int32 value, std::function<int32(int32)> func) {
    t_binary_append<int32>(_bin, value, func);
    return *this;
}

binary& binary::append(uint32 value, std::function<uint32(uint32)> func) {
    t_binary_append<uint32>(_bin, value, func);
    return *this;
}

binary& binary::append(int64 value, std::function<int64(int64)> func) {
    t_binary_append<int64>(_bin, value, func);
    return *this;
}

binary& binary::append(uint64 value, std::function<uint64(uint64)> func) {
    t_binary_append<uint64>(_bin, value, func);
    return *this;
}

binary& binary::append(int128 value, std::function<int128(int128)> func) {
    t_binary_append<int128>(_bin, value, func);
    return *this;
}

binary& binary::append(uint128 value, std::function<uint128(uint128)> func) {
    t_binary_append<uint128>(_bin, value, func);
    return *this;
}

binary& binary::append(float value, std::function<uint32(uint32)> func) {
    binary_append(_bin, value, func);
    return *this;
}

binary& binary::append(double value, std::function<uint64(uint64)> func) {
    binary_append(_bin, value, func);
    return *this;
}

binary& binary::append(const std::string& value) {
    binary_append(_bin, value);
    return *this;
}

binary& binary::append(const binary_t& value) {
    binary_append(_bin, value);
    return *this;
}

binary& binary::append(const binary& value) {
    binary_append(_bin, value);
    return *this;
}

binary& binary::append(const char* value) {
    binary_append(_bin, value);
    return *this;
}

binary& binary::append(const char* value, size_t size) {
    binary_append(_bin, value, size);
    return *this;
}

binary& binary::append(const byte_t* buf, size_t size) {
    binary_append(_bin, buf, size);
    return *this;
}

binary& binary::append(const byte_t* buf, size_t from, size_t to) {
    binary_append(_bin, buf, from, to);
    return *this;
}

binary& binary::fill(size_t count, const byte_t& value) {
    binary_fill(_bin, count, value);
    return *this;
}

binary& binary::byteorder(bool be) {
    _be = be;
    return *this;
}

binary& binary::operator<<(char value) { return push_back(value); }

binary& binary::operator<<(byte_t value) { return push_back(value); }

binary& binary::operator<<(int16 value) { return append(value, _be ? hton16 : nullptr); }

binary& binary::operator<<(uint16 value) { return append(value, _be ? hton16 : nullptr); }

binary& binary::operator<<(int32 value) { return append(value, _be ? hton32 : nullptr); }

binary& binary::operator<<(uint32 value) { return append(value, _be ? hton32 : nullptr); }

binary& binary::operator<<(int64 value) { return append(value, _be ? hton64 : nullptr); }

binary& binary::operator<<(uint64 value) { return append(value, _be ? hton64 : nullptr); }

binary& binary::operator<<(int128 value) { return append(value, _be ? hton128 : nullptr); }

binary& binary::operator<<(uint128 value) { return append(value, _be ? hton128 : nullptr); }

binary& binary::operator<<(float value) { return append(value, _be ? hton32 : nullptr); }

binary& binary::operator<<(double value) { return append(value, _be ? hton64 : nullptr); }

binary& binary::operator<<(const std::string& value) { return append(value); }

binary& binary::operator<<(const binary_t& value) { return append(value); }

binary& binary::operator<<(const binary& value) { return append(value); }

binary& binary::operator<<(const char* value) { return append(value); }

binary& binary::operator=(char value) { return clear().push_back(value); }

binary& binary::operator=(byte_t value) { return clear().push_back(value); }

binary& binary::operator=(int16 value) { return clear().append(value, _be ? hton16 : nullptr); }

binary& binary::operator=(uint16 value) { return clear().append(value, _be ? hton16 : nullptr); }

binary& binary::operator=(int32 value) { return clear().append(value, _be ? hton32 : nullptr); }

binary& binary::operator=(uint32 value) { return clear().append(value, _be ? hton32 : nullptr); }

binary& binary::operator=(int64 value) { return clear().append(value, _be ? hton64 : nullptr); }

binary& binary::operator=(uint64 value) { return clear().append(value, _be ? hton64 : nullptr); }

binary& binary::operator=(int128 value) { return clear().append(value, _be ? hton128 : nullptr); }

binary& binary::operator=(uint128 value) { return clear().append(value, _be ? hton128 : nullptr); }

binary& binary::operator=(float value) { return clear().append(value, _be ? hton32 : nullptr); }

binary& binary::operator=(double value) { return clear().append(value, _be ? hton64 : nullptr); }

binary& binary::operator=(const std::string& value) { return clear().append(value); }

binary& binary::operator=(const binary_t& value) { return clear().append(value); }

binary& binary::operator=(const binary& value) { return clear().append(value); }

binary& binary::operator=(const char* value) { return clear().append(value); }

binary& binary::clear() {
    _bin.clear();
    return *this;
}

binary_t& binary::get() { return _bin; }

const binary_t& binary::get() const { return _bin; }

binary::operator binary_t() { return _bin; }

binary::operator const binary_t&() const { return _bin; }

}  // namespace hotplace
