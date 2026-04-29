/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   binary.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_BASE_BASIC_BINARY__
#define __HOTPLACE_SDK_BASE_BASIC_BINARY__

#include <string.h>

#include <functional>
#include <hotplace/sdk/base/basic/types.hpp>
#include <hotplace/sdk/base/system/endian.hpp>
#include <hotplace/sdk/base/system/uint.hpp>

namespace hotplace {

/**
 * @sample
 *          binary_t bin;
 *          binary_push(bin, 0xff);
 *          uint16 ui16 = 0x1234;
 *          binary_append(bin, ui16, hton16);
 *          uint32 ui32 = 0x1234;
 *          binary_append(bin, ui32, hton32);
 *          // 00000000 : FF 12 34 00 00 12 34 -- -- -- -- -- -- -- -- -- | ..4...4
 *
 *          bin.clear();
 *          binary_append(bin, "We don't playing because we grow old; we grow old because we stop playing.");
 *          // 00000000 : 57 65 20 64 6F 6E 27 74 20 70 6C 61 79 69 6E 67 | We don't playing
 *          // 00000010 : 20 62 65 63 61 75 73 65 20 77 65 20 67 72 6F 77 |  because we grow
 *          // 00000020 : 20 6F 6C 64 3B 20 77 65 20 67 72 6F 77 20 6F 6C |  old; we grow ol
 *          // 00000030 : 64 20 62 65 63 61 75 73 65 20 77 65 20 73 74 6F | d because we sto
 *          // 00000040 : 70 20 70 6C 61 79 69 6E 67 2E -- -- -- -- -- -- | p playing.
 *
 *          bin.clear();
 *          uint128 ui128 = t_htoi<uint128>("0123456789abcdef");
 *          binary_append(bin, ui128, hton128);
 *          // 00000000 : 00 00 00 00 00 00 00 00 01 23 45 67 89 AB CD EF | .........#Eg....
 *
 */
return_t binary_push(binary_t& target, byte_t value);

template <typename T>
return_t t_binary_append(binary_t& target, T value, std::function<T(const T&)> func = nullptr) {
    if (nullptr != func) {
        value = func(value);
    }
    const size_t pos = target.size();
    target.resize(pos + sizeof(T));
    memcpy(target.data() + pos, &value, sizeof(T));
    return errorcode_t::success;
}

return_t binary_append(binary_t& target, int8 value);
return_t binary_append(binary_t& target, uint8 value);
return_t binary_append(binary_t& target, int16 value, std::function<int16(const int16&)> func = nullptr);
return_t binary_append(binary_t& target, uint16 value, std::function<uint16(const uint16&)> func = nullptr);
return_t binary_append(binary_t& target, int32 value, std::function<int32(const int32&)> func = nullptr);
return_t binary_append(binary_t& target, uint32 value, std::function<uint32(const uint32&)> func = nullptr);
return_t binary_append(binary_t& target, int64 value, std::function<int64(const int64&)> func = nullptr);
return_t binary_append(binary_t& target, uint64 value, std::function<uint64(const uint64&)> func = nullptr);
#if defined __SIZEOF_INT128__
return_t binary_append(binary_t& target, int128 value, std::function<int128(const int128&)> func = nullptr);
return_t binary_append(binary_t& target, uint128 value, std::function<uint128(const uint128&)> func = nullptr);
#endif
return_t binary_append(binary_t& target, float value, std::function<uint32(const uint32&)> func = nullptr);
return_t binary_append(binary_t& target, double value, std::function<uint64(const uint64&)> func = nullptr);
return_t binary_append(binary_t& target, const std::string& value);
return_t binary_append(binary_t& target, const binary_t& value);
return_t binary_append(binary_t& target, const char* buf);
return_t binary_append(binary_t& target, const char* buf, size_t size);
return_t binary_append(binary_t& target, const byte_t* buf, size_t size);
return_t binary_append(binary_t& target, const byte_t* buf, size_t from, size_t to);

/**
 * @brief   append
 * @param   binary_t& target [out]
 * @param   uint32 len [in] limited up to sizeof(T)
 *          in case of (len == sizeof(T)) it works like binary_append
 * @param   T value [in]
 * @param   std::function<T(const T&)> func [inopt] hton16, ..., hton128
 * @sample
 *          uint32 ui32 = 0x12345678;
 *
 *          // narrow
 *          // 00000000 : 56 78 -- -- -- -- -- -- -- -- -- -- -- -- -- -- | Vx
 *          binary_t bin;
 *          t_binary_append2<uint32>(bin, sizeof(uint16), ui32, hton32);
 *
 *          // wide
 *          // 00000000 : 00 00 00 00 12 34 56 78 -- -- -- -- -- -- -- -- | .....4Vx
 *          t_binary_append2<uint32>(bin, sizeof(uint64), ui32, hton32);
 */
template <typename T>
return_t t_binary_append2(binary_t& target, uint32 bnlen, T value, std::function<T(const T&)> func = nullptr) {
    if (nullptr != func) {
        value = func(value);
    }
    const size_t pos = target.size();
    uint32 tsize = sizeof(T);
    size_t toffset = 0;
    if (bnlen < tsize) {
        toffset = tsize - bnlen;
        tsize = bnlen;
    }
    target.resize(pos + bnlen);
    if (bnlen > tsize) {
        memset(target.data() + pos, 0, bnlen - tsize);
    }
    memcpy(target.data() + pos + (bnlen - tsize), reinterpret_cast<const byte_t*>(&value) + toffset, tsize);
    return errorcode_t::success;
}

/**
 * @brief   append
 *          bin.clear();
 *          uint128 ui128 = t_htoi<uint128>("0123456789abcdef");
 *          binary_append2(bin, 8, ui128, hton128); // append
 *          // 00000000 : 01 23 45 67 89 AB CD EF -- -- -- -- -- -- -- -- | .#Eg....
 */
return_t binary_append2(binary_t& target, uint32 len, int16 value, std::function<int16(const int16&)> func = nullptr);
return_t binary_append2(binary_t& target, uint32 len, uint16 value, std::function<uint16(const uint16&)> func = nullptr);
return_t binary_append2(binary_t& target, uint32 len, int32 value, std::function<int32(const int32&)> func = nullptr);
return_t binary_append2(binary_t& target, uint32 len, uint32 value, std::function<uint32(const uint32&)> func = nullptr);
return_t binary_append2(binary_t& target, uint32 len, int64 value, std::function<int64(const int64&)> func = nullptr);
return_t binary_append2(binary_t& target, uint32 len, uint64 value, std::function<uint64(const uint64&)> func = nullptr);
#if defined __SIZEOF_INT128__
return_t binary_append2(binary_t& target, uint32 len, int128 value, std::function<int128(const int128&)> func = nullptr);
return_t binary_append2(binary_t& target, uint32 len, uint128 value, std::function<uint128(const uint128&)> func = nullptr);
#endif

/**
 * @brief   overwrite (resize and fill)
 */
template <typename T>
return_t t_binary_load(binary_t& target, size_t bnlen, T value, std::function<T(const T&)> func = nullptr) {
    target.clear();
    target.resize(bnlen);
    if (0 != bnlen) {
        size_t tsize = sizeof(T);
        size_t toffset = 0;
        if (bnlen < tsize) {
            toffset = tsize - bnlen;
            tsize = bnlen;
        }
        if (nullptr != func) {
            value = func(value);
        }
        memcpy(target.data() + (bnlen - tsize), reinterpret_cast<const byte_t*>(&value) + toffset, tsize);
    }
    return errorcode_t::success;
}

return_t binary_load(binary_t& target, size_t limit, int16 value, std::function<int16(const int16&)> func = nullptr);
return_t binary_load(binary_t& target, size_t limit, uint16 value, std::function<uint16(const uint16&)> func = nullptr);
return_t binary_load(binary_t& target, size_t limit, int32 value, std::function<int32(const int32&)> func = nullptr);
return_t binary_load(binary_t& target, size_t limit, uint32 value, std::function<uint32(const uint32&)> func = nullptr);
return_t binary_load(binary_t& target, size_t limit, int64 value, std::function<int64(const int64&)> func = nullptr);
return_t binary_load(binary_t& target, size_t limit, uint64 value, std::function<uint64(const uint64&)> func = nullptr);
#if defined __SIZEOF_INT128__
return_t binary_load(binary_t& target, size_t limit, int128 value, std::function<int128(const int128&)> func = nullptr);
return_t binary_load(binary_t& target, size_t limit, uint128 value, std::function<uint128(const uint128&)> func = nullptr);
#endif
return_t binary_load(binary_t& target, size_t limit, const byte_t* data, size_t len);
return_t binary_fill(binary_t& target, size_t count, const byte_t& value);

static inline binary_t& operator<<(binary_t& lhs, uint8 rhs) {
    lhs.push_back(rhs);
    return lhs;
}

static inline binary_t& operator<<(binary_t& lhs, uint16 rhs) {
    lhs.reserve(lhs.size() + sizeof(uint16));
    t_binary_append<uint16>(lhs, rhs, hton16);
    return lhs;
}

static inline binary_t& operator<<(binary_t& lhs, uint24_t rhs) {
    lhs.reserve(lhs.size() + rhs.capacity());
    lhs.insert(lhs.end(), rhs.data, rhs.data + rhs.capacity());
    return lhs;
}

static inline binary_t& operator<<(binary_t& lhs, uint32 rhs) {
    lhs.reserve(lhs.size() + sizeof(uint32));
    t_binary_append<uint32>(lhs, rhs, hton32);
    return lhs;
}

static inline binary_t& operator<<(binary_t& lhs, uint48_t rhs) {
    lhs.reserve(lhs.size() + rhs.capacity());
    lhs.insert(lhs.end(), rhs.data, rhs.data + rhs.capacity());
    return lhs;
}

static inline binary_t& operator<<(binary_t& lhs, uint64 rhs) {
    lhs.reserve(lhs.size() + sizeof(uint64));
    t_binary_append<uint64>(lhs, rhs, hton64);
    return lhs;
}

#if defined __SIZEOF_INT128__
static inline binary_t& operator<<(binary_t& lhs, uint128 rhs) {
    lhs.reserve(lhs.size() + sizeof(uint128));
    t_binary_append<uint128>(lhs, rhs, hton128);
    return lhs;
}
#endif

static inline binary_t& operator<<(binary_t& lhs, char* rhs) {
    if (nullptr != rhs) {
        const size_t len = strlen(rhs);
        if (0 != len) {
            lhs.reserve(lhs.size() + len);
            lhs.insert(lhs.end(), rhs, rhs + len);
        }
    }
    return lhs;
}

static inline binary_t& operator<<(binary_t& lhs, const std::string& rhs) {
    if (false == rhs.empty()) {
        lhs.reserve(lhs.size() + rhs.size());
        lhs.insert(lhs.end(), rhs.begin(), rhs.end());
    }
    return lhs;
}

static inline binary_t& operator<<(binary_t& lhs, const binary_t& rhs) {
    if (false == rhs.empty()) {
        lhs.reserve(lhs.size() + rhs.size());
        lhs.insert(lhs.end(), rhs.begin(), rhs.end());
    }
    return lhs;
}

/**
 * @brief   util
 */
std::string bin2str(const binary_t& bin);

/**
 * @brief   util
 */
binary_t str2bin(const std::string& source);

/**
 * @brief   binary to integer
 * @remarks
 *          bin.clear();
 *          binary_append(bin, uint32(1), hton32);
 *          ui32 = t_binary_to_integer<uint32>(bin);
 *          _test_case.assert(1 == ui32, __FUNCTION__, "bin32 to uint32");
 *
 *          bin.clear();
 *          binary_append(bin, uint32(1), hton32);
 *          ui64 = t_binary_to_integer<uint64>(bin);
 *          _test_case.assert(1 == ui64, __FUNCTION__, "bin32 to uint64");
 *
 *          bin.clear();
 *          binary_append(bin, uint8(1));
 *          ui32 = t_binary_to_integer<uint32>(bin);
 *          _test_case.assert(1 == ui32, __FUNCTION__, "bin8 to uint32");
 */
template <typename T>
T t_binary_to_integer(const byte_t* bstr, size_t size, return_t& errorcode) {
    T value = 0;
    if (nullptr != bstr) {
        size_t tsize = sizeof(T);
        if (tsize <= size) {
            value = *reinterpret_cast<const T*>(bstr);
            if (tsize > 1) {
                value = convert_endian(value);  // host endian
            }
        } else {
            binary_t bin;
            binary_load(bin, tsize, bstr, size);
            value = *reinterpret_cast<const T*>(bin.data());
            if (tsize > 1) {
                value = convert_endian(value);  // host endian
            }
        }
    } else {
        errorcode = errorcode_t::invalid_parameter;
    }
    return value;
}

template <typename T>
T t_binary_to_integer(const byte_t* bstr, size_t size) {
    return_t errorcode = errorcode_t::success;
    return t_binary_to_integer<T>(bstr, size, errorcode);
}

template <typename T>
T t_binary_to_integer(const binary_t& bin, return_t& errorcode) {
    return t_binary_to_integer<T>(bin.data(), bin.size(), errorcode);
}

template <typename T>
T t_binary_to_integer(const binary_t& bin) {
    return_t errorcode = errorcode_t::success;
    return t_binary_to_integer<T>(bin, errorcode);
}

}  // namespace hotplace

#endif
