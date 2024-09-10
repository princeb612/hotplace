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

#include <ostream>
#include <sdk/base/basic/ieee754.hpp>
#include <sdk/base/binary.hpp>
#include <sdk/base/inline.hpp>

namespace hotplace {

return_t binary_push(binary_t& target, byte_t rhs) {
    return_t ret = errorcode_t::success;
    target.insert(target.end(), rhs);
    return ret;
}

return_t binary_append(binary_t& target, int16 rhs, std::function<int16(int16)> func) {
    return_t ret = errorcode_t::success;
    if (func) {
        int16 temp = rhs;
        rhs = func(temp);
    }
    target.insert(target.end(), (byte_t*)&rhs, (byte_t*)&rhs + sizeof(rhs));
    return ret;
}

return_t binary_append(binary_t& target, uint16 rhs, std::function<uint16(uint16)> func) {
    return_t ret = errorcode_t::success;
    if (func) {
        uint16 temp = rhs;
        rhs = func(temp);
    }
    target.insert(target.end(), (byte_t*)&rhs, (byte_t*)&rhs + sizeof(rhs));
    return ret;
}

return_t binary_append(binary_t& target, int32 rhs, std::function<int32(int32)> func) {
    return_t ret = errorcode_t::success;
    if (func) {
        int32 temp = rhs;
        rhs = func(temp);
    }
    target.insert(target.end(), (byte_t*)&rhs, (byte_t*)&rhs + sizeof(rhs));
    return ret;
}

return_t binary_append(binary_t& target, uint32 rhs, std::function<uint32(uint32)> func) {
    return_t ret = errorcode_t::success;
    if (func) {
        uint32 temp = rhs;
        rhs = func(temp);
    }
    target.insert(target.end(), (byte_t*)&rhs, (byte_t*)&rhs + sizeof(rhs));
    return ret;
}

return_t binary_append(binary_t& target, int64 rhs, std::function<int64(int64)> func) {
    return_t ret = errorcode_t::success;
    if (func) {
        int64 temp = rhs;
        rhs = func(temp);
    }
    target.insert(target.end(), (byte_t*)&rhs, (byte_t*)&rhs + sizeof(rhs));
    return ret;
}

return_t binary_append(binary_t& target, uint64 rhs, std::function<uint64(uint64)> func) {
    return_t ret = errorcode_t::success;
    if (func) {
        uint64 temp = rhs;
        rhs = func(temp);
    }
    target.insert(target.end(), (byte_t*)&rhs, (byte_t*)&rhs + sizeof(rhs));
    return ret;
}

return_t binary_append(binary_t& target, int128 rhs, std::function<int128(int128)> func, size_t len) {
    return_t ret = errorcode_t::success;
    if (func) {
        int128 temp = rhs;
        rhs = func(temp);
    }
    size_t limit = sizeof(rhs);
    if (len > limit) {
        len = limit;
    }
    size_t offset = limit - len;
    target.insert(target.end(), (byte_t*)&rhs + offset, (byte_t*)&rhs + sizeof(rhs));
    return ret;
}

return_t binary_append(binary_t& target, uint128 rhs, std::function<uint128(uint128)> func, size_t len) {
    return_t ret = errorcode_t::success;
    if (func) {
        uint128 temp = rhs;
        rhs = func(temp);
    }
    size_t limit = sizeof(rhs);
    if (len > limit) {
        len = limit;
    }
    size_t offset = limit - len;
    target.insert(target.end(), (byte_t*)&rhs + offset, (byte_t*)&rhs + sizeof(rhs));
    return ret;
}

return_t binary_append(binary_t& target, float rhs, std::function<uint32(uint32)> func) {
    return_t ret = errorcode_t::success;
    uint32 fp = binary32_from_fp32(rhs);
    if (func) {
        fp = func(fp);
    }
    target.insert(target.end(), (byte_t*)&fp, (byte_t*)&fp + sizeof(fp));
    return ret;
}

return_t binary_append(binary_t& target, double rhs, std::function<uint64(uint64)> func) {
    return_t ret = errorcode_t::success;
    uint64 fp = binary64_from_fp64(rhs);
    if (func) {
        fp = func(fp);
    }
    target.insert(target.end(), (byte_t*)&fp, (byte_t*)&fp + sizeof(fp));
    return ret;
}

return_t binary_append(binary_t& target, const std::string& rhs) {
    return_t ret = errorcode_t::success;
    target.insert(target.end(), rhs.begin(), rhs.end());
    return ret;
}

return_t binary_append(binary_t& target, const binary_t& rhs) {
    return_t ret = errorcode_t::success;
    target.insert(target.end(), rhs.begin(), rhs.end());
    return ret;
}

return_t binary_append(binary_t& target, const binary& rhs) {
    return_t ret = errorcode_t::success;
    target << rhs.get();
    return ret;
}

return_t binary_append(binary_t& target, const char* rhs) {
    return_t ret = errorcode_t::success;
    if (rhs) {
        target.insert(target.end(), rhs, rhs + strlen(rhs));
    } else {
        ret = errorcode_t::invalid_parameter;
    }
    return ret;
}

return_t binary_append(binary_t& target, const char* buf, size_t size) {
    return_t ret = errorcode_t::success;
    if (buf) {
        target.insert(target.end(), buf, buf + size);
    } else {
        ret = errorcode_t::invalid_parameter;
    }
    return ret;
}

return_t binary_append(binary_t& target, const byte_t* buf, size_t size) {
    return_t ret = errorcode_t::success;
    if (buf) {
        target.insert(target.end(), buf, buf + size);
    } else {
        ret = errorcode_t::invalid_parameter;
    }
    return ret;
}

return_t binary_append(binary_t& target, const byte_t* buf, size_t from, size_t to) {
    return_t ret = errorcode_t::success;
    if (buf && (from < to)) {
        target.insert(target.end(), buf + from, buf + to);
    } else {
        ret = errorcode_t::invalid_parameter;
    }
    return ret;
}

return_t binary_load(binary_t& target, uint32 bnlen, byte_t* data, uint32 len) {
    return_t ret = errorcode_t::success;
    target.clear();
    target.resize(bnlen);
    if (data) {
        if (len > bnlen) {
            len = bnlen;
        }
        memcpy(&target[0] + (bnlen - len), data, len);
    } else {
        ret = errorcode_t::invalid_parameter;
    }
    return ret;
}

return_t binary_fill(binary_t& target, size_t count, const byte_t& value) {
    return_t ret = errorcode_t::success;
    for (auto i = 0; i < count; i++) {
        target.push_back(value);
    }
    return ret;
}

binary::binary() {}

binary::binary(const binary& rhs) : _bin(rhs._bin) {}

binary::binary(binary&& rhs) : _bin(std::move(rhs._bin)) {}

binary::binary(char rhs) { push_back(rhs); }

binary::binary(byte_t rhs) { push_back(rhs); }

binary::binary(int16 rhs) { append(rhs); }

binary::binary(uint16 rhs) { append(rhs); }

binary::binary(int32 rhs) { append(rhs); }

binary::binary(uint32 rhs) { append(rhs); }

binary::binary(int64 rhs) { append(rhs); }

binary::binary(uint64 rhs) { append(rhs); }

binary::binary(int128 rhs) { append(rhs); }

binary::binary(uint128 rhs) { append(rhs); }

binary::binary(float rhs) { append(rhs); }

binary::binary(double rhs) { append(rhs); }

binary::binary(const std::string& rhs) { append(rhs); }

binary::binary(const char* rhs) { append(rhs); }

binary::binary(const byte_t* buf, size_t size) { append(buf, size); }

binary::binary(const binary_t& rhs) : _bin(rhs) {}

binary::binary(binary_t&& rhs) : _bin(std::move(rhs)) {}

binary& binary::push_back(byte_t rhs) {
    binary_push(_bin, rhs);
    return *this;
}

binary& binary::append(int16 rhs, std::function<int16(int16)> func) {
    binary_append(_bin, rhs, func);
    return *this;
}

binary& binary::append(uint16 rhs, std::function<uint16(uint16)> func) {
    binary_append(_bin, rhs, func);
    return *this;
}

binary& binary::append(int32 rhs, std::function<int32(int32)> func) {
    binary_append(_bin, rhs, func);
    return *this;
}

binary& binary::append(uint32 rhs, std::function<uint32(uint32)> func) {
    binary_append(_bin, rhs, func);
    return *this;
}

binary& binary::append(int64 rhs, std::function<int64(int64)> func) {
    binary_append(_bin, rhs, func);
    return *this;
}

binary& binary::append(uint64 rhs, std::function<uint64(uint64)> func) {
    binary_append(_bin, rhs, func);
    return *this;
}

binary& binary::append(int128 rhs, std::function<int128(int128)> func, size_t len) {
    binary_append(_bin, rhs, func, len);
    return *this;
}

binary& binary::append(uint128 rhs, std::function<uint128(uint128)> func, size_t len) {
    binary_append(_bin, rhs, func, len);
    return *this;
}

binary& binary::append(float rhs, std::function<uint32(uint32)> func) {
    binary_append(_bin, rhs, func);
    return *this;
}

binary& binary::append(double rhs, std::function<uint64(uint64)> func) {
    binary_append(_bin, rhs, func);
    return *this;
}

binary& binary::append(const std::string& rhs) {
    binary_append(_bin, rhs);
    return *this;
}

binary& binary::append(const binary_t& rhs) {
    binary_append(_bin, rhs);
    return *this;
}

binary& binary::append(const binary& rhs) {
    binary_append(_bin, rhs);
    return *this;
}

binary& binary::append(const char* rhs) {
    binary_append(_bin, rhs);
    return *this;
}

binary& binary::append(const char* rhs, size_t size) {
    binary_append(_bin, rhs, size);
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

binary& binary::operator<<(char rhs) { return push_back(rhs); }

binary& binary::operator<<(byte_t rhs) { return push_back(rhs); }

binary& binary::operator<<(int16 rhs) { return append(rhs); }

binary& binary::operator<<(uint16 rhs) { return append(rhs); }

binary& binary::operator<<(int32 rhs) { return append(rhs); }

binary& binary::operator<<(uint32 rhs) { return append(rhs); }

binary& binary::operator<<(int64 rhs) { return append(rhs); }

binary& binary::operator<<(uint64 rhs) { return append(rhs); }

binary& binary::operator<<(int128 rhs) { return append(rhs); }

binary& binary::operator<<(uint128 rhs) { return append(rhs); }

binary& binary::operator<<(float rhs) { return append(rhs); }

binary& binary::operator<<(double rhs) { return append(rhs); }

binary& binary::operator<<(const std::string& rhs) { return append(rhs); }

binary& binary::operator<<(const binary_t& rhs) { return append(rhs); }

binary& binary::operator<<(const binary& rhs) { return append(rhs); }

binary& binary::operator<<(const char* rhs) { return append(rhs); }

binary& binary::operator=(char rhs) { return clear().push_back(rhs); }

binary& binary::operator=(byte_t rhs) { return clear().push_back(rhs); }

binary& binary::operator=(int16 rhs) { return clear().append(rhs); }

binary& binary::operator=(uint16 rhs) { return clear().append(rhs); }

binary& binary::operator=(int32 rhs) { return clear().append(rhs); }

binary& binary::operator=(uint32 rhs) { return clear().append(rhs); }

binary& binary::operator=(int64 rhs) { return clear().append(rhs); }

binary& binary::operator=(uint64 rhs) { return clear().append(rhs); }

binary& binary::operator=(int128 rhs) { return clear().append(rhs); }

binary& binary::operator=(uint128 rhs) { return clear().append(rhs); }

binary& binary::operator=(float rhs) { return clear().append(rhs); }

binary& binary::operator=(double rhs) { return clear().append(rhs); }

binary& binary::operator=(const std::string& rhs) { return clear().append(rhs); }

binary& binary::operator=(const binary_t& rhs) { return clear().append(rhs); }

binary& binary::operator=(const binary& rhs) { return clear().append(rhs); }

binary& binary::operator=(const char* rhs) { return clear().append(rhs); }

binary& binary::clear() {
    _bin.clear();
    return *this;
}

binary_t& binary::get() { return _bin; }

const binary_t& binary::get() const { return _bin; }

binary::operator binary_t() { return _bin; }

binary::operator const binary_t&() const { return _bin; }

}  // namespace hotplace
