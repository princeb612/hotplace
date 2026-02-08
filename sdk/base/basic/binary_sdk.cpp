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

#include <hotplace/sdk/base/basic/binary.hpp>
#include <hotplace/sdk/base/basic/ieee754.hpp>  // binary32_from_fp32, binary64_from_fp64
#include <ostream>

namespace hotplace {

return_t binary_push(binary_t& target, byte_t rhs) {
    target.push_back(rhs);
    return errorcode_t::success;
}

return_t binary_append(binary_t& target, int8 value) {
    target.push_back(static_cast<byte_t>(value));
    return errorcode_t::success;
}

return_t binary_append(binary_t& target, uint8 value) {
    target.push_back(value);
    return errorcode_t::success;
}

return_t binary_append(binary_t& target, int16 value, std::function<int16(const int16&)> func) { return t_binary_append<int16>(target, value, func); }

return_t binary_append(binary_t& target, uint16 value, std::function<uint16(const uint16&)> func) { return t_binary_append<uint16>(target, value, func); }

return_t binary_append(binary_t& target, int32 value, std::function<int32(const int32&)> func) { return t_binary_append<int32>(target, value, func); }

return_t binary_append(binary_t& target, uint32 value, std::function<uint32(const uint32&)> func) { return t_binary_append<uint32>(target, value, func); }

return_t binary_append(binary_t& target, int64 value, std::function<int64(const int64&)> func) { return t_binary_append<int64>(target, value, func); }

return_t binary_append(binary_t& target, uint64 value, std::function<uint64(const uint64&)> func) { return t_binary_append<uint64>(target, value, func); }

#if defined __SIZEOF_INT128__
return_t binary_append(binary_t& target, int64 value, std::function<int128(const int128&)> func) { return t_binary_append<int128>(target, value, func); }

return_t binary_append(binary_t& target, uint128 value, std::function<uint128(const uint128&)> func) { return t_binary_append<uint128>(target, value, func); }
#endif

return_t binary_append(binary_t& target, float value, std::function<uint32(const uint32&)> func) {
    uint32 fp = binary32_from_fp32(value);
    if (nullptr != func) {
        fp = func(fp);
    }
    const size_t pos = target.size();
    target.resize(pos + sizeof(fp));
    memcpy(target.data() + pos, &fp, sizeof(fp));
    return errorcode_t::success;
}

return_t binary_append(binary_t& target, double value, std::function<uint64(const uint64&)> func) {
    uint64 fp = binary64_from_fp64(value);
    if (nullptr != func) {
        fp = func(fp);
    }
    const size_t pos = target.size();
    target.resize(pos + sizeof(fp));
    memcpy(target.data() + pos, &fp, sizeof(fp));
    return errorcode_t::success;
}

return_t binary_append(binary_t& target, const std::string& value) {
    if (true == value.empty()) {
        // do nothing
    } else {
        target.reserve(target.size() + value.size());
        target.insert(target.end(), value.begin(), value.end());
    }
    return errorcode_t::success;
}

return_t binary_append(binary_t& target, const binary_t& value) {
    if (true == value.empty()) {
        // do nothing
    } else {
        target.reserve(target.size() + value.size());
        target.insert(target.end(), value.begin(), value.end());
    }
    return errorcode_t::success;
}

return_t binary_append(binary_t& target, const binary& value) {
    const binary_t& src = value.get();
    if (false == src.empty()) {
        target.reserve(target.size() + src.size());
        target.insert(target.end(), src.begin(), src.end());
    }
    return errorcode_t::success;
}

return_t binary_append(binary_t& target, const char* value) {
    return_t ret = errorcode_t::success;
    if (nullptr == value) {
        ret = errorcode_t::invalid_parameter;
    } else {
        const size_t len = strlen(value);
        if (0 != len) {
            target.reserve(target.size() + len);
            target.insert(target.end(), value, value + len);
        }
    }
    return ret;
}

return_t binary_append(binary_t& target, const char* buf, size_t size) {
    return_t ret = errorcode_t::success;
    if (nullptr == buf) {
        ret = errorcode_t::invalid_parameter;
    } else {
        if (0 != size) {
            target.reserve(target.size() + size);
            target.insert(target.end(), buf, buf + size);
        }
    }
    return errorcode_t::success;
}

return_t binary_append(binary_t& target, const byte_t* buf, size_t size) {
    return_t ret = errorcode_t::success;
    if (nullptr == buf) {
        ret = errorcode_t::invalid_parameter;
    } else {
        if (0 != size) {
            target.reserve(target.size() + size);
            target.insert(target.end(), buf, buf + size);
        }
    }
    return ret;
}

return_t binary_append(binary_t& target, const byte_t* buf, size_t from, size_t to) {
    return_t ret = errorcode_t::success;
    if ((nullptr == buf) || (from >= to)) {
        ret = errorcode_t::invalid_parameter;
    } else {
        const size_t len = to - from;
        target.reserve(target.size() + len);
        target.insert(target.end(), buf + from, buf + to);
    }
    return ret;
}

return_t binary_append2(binary_t& target, uint32 len, int16 value, std::function<int16(const int16&)> func) {
    return t_binary_append2<int16>(target, len, value, func);
}

return_t binary_append2(binary_t& target, uint32 len, uint16 value, std::function<uint16(const uint16&)> func) {
    return t_binary_append2<uint16>(target, len, value, func);
}

return_t binary_append2(binary_t& target, uint32 len, int32 value, std::function<int32(const int32&)> func) {
    return t_binary_append2<int32>(target, len, value, func);
}

return_t binary_append2(binary_t& target, uint32 len, uint32 value, std::function<uint32(const uint32&)> func) {
    return t_binary_append2<uint32>(target, len, value, func);
}

return_t binary_append2(binary_t& target, uint32 len, int64 value, std::function<int64(const int64&)> func) {
    return t_binary_append2<int64>(target, len, value, func);
}

return_t binary_append2(binary_t& target, uint32 len, uint64 value, std::function<uint64(const uint64&)> func) {
    return t_binary_append2<uint64>(target, len, value, func);
}

#if defined __SIZEOF_INT128__
return_t binary_append2(binary_t& target, uint32 len, int128 value, std::function<int128(const int128&)> func) {
    return t_binary_append2<int128>(target, len, value, func);
}

return_t binary_append2(binary_t& target, uint32 len, uint128 value, std::function<uint128(const uint128&)> func) {
    return t_binary_append2<uint128>(target, len, value, func);
}
#endif

return_t binary_load(binary_t& bn, uint32 bnlen, int16 value, std::function<int16(const int16&)> func) { return t_binary_load<int16>(bn, bnlen, value, func); }

return_t binary_load(binary_t& bn, uint32 bnlen, uint16 value, std::function<uint16(const uint16&)> func) {
    return t_binary_load<uint16>(bn, bnlen, value, func);
}

return_t binary_load(binary_t& bn, uint32 bnlen, int32 value, std::function<int32(const int32&)> func) { return t_binary_load<int32>(bn, bnlen, value, func); }

return_t binary_load(binary_t& bn, uint32 bnlen, uint32 value, std::function<uint32(const uint32&)> func) {
    return t_binary_load<uint32>(bn, bnlen, value, func);
}

return_t binary_load(binary_t& bn, uint32 bnlen, int64 value, std::function<int64(const int64&)> func) { return t_binary_load<int64>(bn, bnlen, value, func); }

return_t binary_load(binary_t& bn, uint32 bnlen, uint64 value, std::function<uint64(const uint64&)> func) {
    return t_binary_load<uint64>(bn, bnlen, value, func);
}

#if defined __SIZEOF_INT128__
return_t binary_load(binary_t& bn, uint32 bnlen, int128 value, std::function<int128(const int128&)> func) {
    return t_binary_load<int128>(bn, bnlen, value, func);
}

return_t binary_load(binary_t& bn, uint32 bnlen, uint128 value, std::function<uint128(const uint128&)> func) {
    return t_binary_load<uint128>(bn, bnlen, value, func);
}
#endif

return_t binary_load(binary_t& target, uint32 bnlen, const byte_t* data, uint32 len) {
    return_t ret = errorcode_t::success;
    if (nullptr == data) {
        ret = errorcode_t::invalid_parameter;
    } else {
        target.resize(bnlen);
        if (len > bnlen) {
            len = bnlen;
        }
        memcpy(target.data() + (bnlen - len), data, len);
    }
    return ret;
}

return_t binary_fill(binary_t& target, size_t count, const byte_t& value) {
    if (0 == count) {
        // do nothing
    } else {
        const size_t pos = target.size();
        target.resize(pos + count);
        memset(target.data() + pos, value, count);
    }
    return errorcode_t::success;
}

}  // namespace hotplace
