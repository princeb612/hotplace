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
#include <sdk/base/basic/binary.hpp>
#include <sdk/base/basic/ieee754.hpp>
#include <sdk/base/inline.hpp>

namespace hotplace {

return_t binary_push(binary_t& target, byte_t rhs) {
    return_t ret = errorcode_t::success;
    target.insert(target.end(), rhs);
    return ret;
}

return_t binary_append(binary_t& target, int16 value, std::function<int16(int16)> func) { return t_binary_append<int16>(target, value, func); }

return_t binary_append(binary_t& target, uint16 value, std::function<uint16(uint16)> func) { return t_binary_append<uint16>(target, value, func); }

return_t binary_append(binary_t& target, int32 value, std::function<int32(int32)> func) { return t_binary_append<int32>(target, value, func); }

return_t binary_append(binary_t& target, uint32 value, std::function<uint32(uint32)> func) { return t_binary_append<uint32>(target, value, func); }

return_t binary_append(binary_t& target, int64 value, std::function<int64(int64)> func) { return t_binary_append<int64>(target, value, func); }

return_t binary_append(binary_t& target, uint64 value, std::function<uint64(uint64)> func) { return t_binary_append<uint64>(target, value, func); }

return_t binary_append(binary_t& target, int64 value, std::function<int128(int128)> func) { return t_binary_append<int128>(target, value, func); }

return_t binary_append(binary_t& target, uint128 value, std::function<uint128(uint128)> func) { return t_binary_append<uint128>(target, value, func); }

return_t binary_append(binary_t& target, float value, std::function<uint32(uint32)> func) {
    return_t ret = errorcode_t::success;
    uint32 fp = binary32_from_fp32(value);
    if (func) {
        fp = func(fp);
    }
    target.insert(target.end(), (byte_t*)&fp, (byte_t*)&fp + sizeof(fp));
    return ret;
}

return_t binary_append(binary_t& target, double value, std::function<uint64(uint64)> func) {
    return_t ret = errorcode_t::success;
    uint64 fp = binary64_from_fp64(value);
    if (func) {
        fp = func(fp);
    }
    target.insert(target.end(), (byte_t*)&fp, (byte_t*)&fp + sizeof(fp));
    return ret;
}

return_t binary_append(binary_t& target, const std::string& value) {
    return_t ret = errorcode_t::success;
    target.insert(target.end(), value.begin(), value.end());
    return ret;
}

return_t binary_append(binary_t& target, const binary_t& value) {
    return_t ret = errorcode_t::success;
    target.insert(target.end(), value.begin(), value.end());
    return ret;
}

return_t binary_append(binary_t& target, const binary& value) {
    return_t ret = errorcode_t::success;
    target << value.get();
    return ret;
}

return_t binary_append(binary_t& target, const char* value) {
    return_t ret = errorcode_t::success;
    if (value) {
        target.insert(target.end(), value, value + strlen(value));
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

return_t binary_append2(binary_t& target, uint32 len, int16 value, std::function<int16(int16)> func) {
    return t_binary_append2<int16>(target, len, value, func);
}

return_t binary_append2(binary_t& target, uint32 len, uint16 value, std::function<uint16(uint16)> func) {
    return t_binary_append2<uint16>(target, len, value, func);
}

return_t binary_append2(binary_t& target, uint32 len, int32 value, std::function<int32(int32)> func) {
    return t_binary_append2<int32>(target, len, value, func);
}

return_t binary_append2(binary_t& target, uint32 len, uint32 value, std::function<uint32(uint32)> func) {
    return t_binary_append2<uint32>(target, len, value, func);
}

return_t binary_append2(binary_t& target, uint32 len, int64 value, std::function<int64(int64)> func) {
    return t_binary_append2<int64>(target, len, value, func);
}

return_t binary_append2(binary_t& target, uint32 len, uint64 value, std::function<uint64(uint64)> func) {
    return t_binary_append2<uint64>(target, len, value, func);
}

return_t binary_append2(binary_t& target, uint32 len, int128 value, std::function<int128(int128)> func) {
    return t_binary_append2<int128>(target, len, value, func);
}

return_t binary_append2(binary_t& target, uint32 len, uint128 value, std::function<uint128(uint128)> func) {
    return t_binary_append2<uint128>(target, len, value, func);
}

return_t binary_load(binary_t& bn, uint32 bnlen, int16 value, std::function<int16(int16)> func) { return t_binary_load<int16>(bn, bnlen, value, func); }

return_t binary_load(binary_t& bn, uint32 bnlen, uint16 value, std::function<uint16(uint16)> func) { return t_binary_load<uint16>(bn, bnlen, value, func); }

return_t binary_load(binary_t& bn, uint32 bnlen, int32 value, std::function<int32(int32)> func) { return t_binary_load<int32>(bn, bnlen, value, func); }

return_t binary_load(binary_t& bn, uint32 bnlen, uint32 value, std::function<uint32(uint32)> func) { return t_binary_load<uint32>(bn, bnlen, value, func); }

return_t binary_load(binary_t& bn, uint32 bnlen, int64 value, std::function<int64(int64)> func) { return t_binary_load<int64>(bn, bnlen, value, func); }

return_t binary_load(binary_t& bn, uint32 bnlen, uint64 value, std::function<uint64(uint64)> func) { return t_binary_load<uint64>(bn, bnlen, value, func); }

return_t binary_load(binary_t& bn, uint32 bnlen, int128 value, std::function<int128(int128)> func) { return t_binary_load<int128>(bn, bnlen, value, func); }

return_t binary_load(binary_t& bn, uint32 bnlen, uint128 value, std::function<uint128(uint128)> func) { return t_binary_load<uint128>(bn, bnlen, value, func); }

return_t binary_load(binary_t& target, uint32 bnlen, const byte_t* data, uint32 len) {
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

}  // namespace hotplace
