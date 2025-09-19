/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
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

namespace hotplace {

/*
 * @brief   std::vector<unsigned char> utility
 */
class binary {
   public:
    binary();
    binary(const binary& rhs);
    binary(binary&& rhs);

    binary(char rhs);
    binary(byte_t rhs);
    binary(int16 rhs);
    binary(uint16 rhs);
    binary(int32 rhs);
    binary(uint32 rhs);
    binary(int64 rhs);
    binary(uint64 rhs);
#if defined __SIZEOF_INT128__
    binary(int128 rhs);
    binary(uint128 rhs);
#endif
    binary(float rhs);
    binary(double rhs);
    binary(const std::string& rhs);
    binary(const char* rhs);
    binary(const byte_t* buf, size_t size);

    binary(const binary_t& rhs);
    binary(binary_t&& rhs);

    binary& set(const binary& rhs);
    binary& set(const binary_t& rhs);
    binary& set(binary_t&& rhs);

    binary& push_back(byte_t rhs);

    /*
     * @brief   append
     * @sample
     *          uint32 data = 100;
     *          b.append(data);          // 64000000 little endian
     *          b.append(data, hton32);  // 00000064 big endian
     */
    binary& append(int16 value, std::function<int16(int16)> func = nullptr);
    binary& append(uint16 value, std::function<uint16(uint16)> func = nullptr);
    binary& append(int32 value, std::function<int32(int32)> func = nullptr);
    binary& append(uint32 value, std::function<uint32(uint32)> func = nullptr);
    binary& append(int64 value, std::function<int64(int64)> func = nullptr);
    binary& append(uint64 value, std::function<uint64(uint64)> func = nullptr);
#if defined __SIZEOF_INT128__
    binary& append(int128 value, std::function<int128(int128)> func = nullptr);
    binary& append(uint128 value, std::function<uint128(uint128)> func = nullptr);
#endif
    binary& append(float value, std::function<uint32(uint32)> func = nullptr);
    binary& append(double value, std::function<uint64(uint64)> func = nullptr);
    /**
     * @sample
     *          b.append("token");
     *          00000000 : 74 6F 6B 65 6E -- -- -- -- -- -- -- -- -- -- -- | token
     */
    binary& append(const std::string& value);
    binary& append(const binary_t& value);
    binary& append(const binary& value);
    binary& append(const char* value);
    binary& append(const char* buf, size_t size);
    binary& append(const byte_t* buf, size_t size);
    binary& append(const byte_t* buf, size_t from, size_t to);

    binary& fill(size_t count, const byte_t& value);

    /**
     * @brief   byte order
     * @sample
     *          b.byteorder(false);
     *          b << ui32;          // system endian
     *          b.byteorder(true);
     *          b << ui32;          // big endian
     */
    binary& byteorder(bool be);

    binary& operator<<(char value);
    binary& operator<<(byte_t value);
    binary& operator<<(int16 value);
    binary& operator<<(uint16 value);
    binary& operator<<(int32 value);
    binary& operator<<(uint32 value);
    binary& operator<<(int64 value);
    binary& operator<<(uint64 value);
#if defined __SIZEOF_INT128__
    binary& operator<<(int128 value);
    binary& operator<<(uint128 value);
#endif
    binary& operator<<(float value);
    binary& operator<<(double value);
    binary& operator<<(const std::string& value);
    binary& operator<<(const binary_t& value);
    binary& operator<<(const binary& value);
    binary& operator<<(const char* value);

    binary& operator=(char value);
    binary& operator=(byte_t value);
    binary& operator=(int16 value);
    binary& operator=(uint16 value);
    binary& operator=(int32 value);
    binary& operator=(uint32 value);
    binary& operator=(int64 value);
    binary& operator=(uint64 value);
#if defined __SIZEOF_INT128__
    binary& operator=(int128 value);
    binary& operator=(uint128 value);
#endif
    binary& operator=(float value);
    binary& operator=(double value);
    binary& operator=(const std::string& value);
    binary& operator=(const binary_t& value);
    binary& operator=(binary_t&& value);
    binary& operator=(const binary& value);
    binary& operator=(const char* value);

    binary& clear();

    binary_t& get();
    const binary_t& get() const;
    operator binary_t();
    operator const binary_t&() const;
    size_t size();
    size_t size() const;

   private:
    binary_t _bin;
    bool _be;
};

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
return_t binary_push(binary_t& target, byte_t rhs);

template <typename T>
return_t t_binary_append(binary_t& target, T value, std::function<T(T)> func = nullptr) {
    return_t ret = errorcode_t::success;
    if (func) {
        T temp = value;
        value = func(temp);
    }
    target.insert(target.end(), (byte_t*)&value, (byte_t*)&value + sizeof(T));
    return ret;
}

return_t binary_append(binary_t& target, int8 value);
return_t binary_append(binary_t& target, uint8 value);
return_t binary_append(binary_t& target, int16 value, std::function<int16(int16)> func = nullptr);
return_t binary_append(binary_t& target, uint16 value, std::function<uint16(uint16)> func = nullptr);
return_t binary_append(binary_t& target, int32 value, std::function<int32(int32)> func = nullptr);
return_t binary_append(binary_t& target, uint32 value, std::function<uint32(uint32)> func = nullptr);
return_t binary_append(binary_t& target, int64 value, std::function<int64(int64)> func = nullptr);
return_t binary_append(binary_t& target, uint64 value, std::function<uint64(uint64)> func = nullptr);
#if defined __SIZEOF_INT128__
return_t binary_append(binary_t& target, int128 value, std::function<int128(int128)> func = nullptr);
return_t binary_append(binary_t& target, uint128 value, std::function<uint128(uint128)> func = nullptr);
#endif
return_t binary_append(binary_t& target, float value, std::function<uint32(uint32)> func = nullptr);
return_t binary_append(binary_t& target, double value, std::function<uint64(uint64)> func = nullptr);
return_t binary_append(binary_t& target, const std::string& rhs);
return_t binary_append(binary_t& target, const binary_t& rhs);
return_t binary_append(binary_t& target, const binary& rhs);
return_t binary_append(binary_t& target, const char* rhs);
return_t binary_append(binary_t& target, const char* buf, size_t size);
return_t binary_append(binary_t& target, const byte_t* buf, size_t size);
return_t binary_append(binary_t& target, const byte_t* buf, size_t from, size_t to);

/**
 * @brief   append
 * @param   binary_t& target [out]
 * @param   uint32 len [in] limited up to sizeof(T)
 *          in case of (len == sizeof(T)) it works like binary_append
 * @param   T value [in]
 * @param   std::function<T(T)> func [inopt] hton16, ..., hton128
 */
template <typename T>
return_t t_binary_append2(binary_t& target, uint32 bnlen, T value, std::function<T(T)> func = nullptr) {
    return_t ret = errorcode_t::success;
    size_t pos = target.size();
    uint32 tsize = sizeof(T);
    size_t toffset = 0;
    if (func) {
        T temp = value;
        value = func(temp);
    }
    if (bnlen >= tsize) {
        size_t offset = bnlen - tsize;
        while (offset--) {
            binary_push(target, 0);
        }
    } else {
        toffset = tsize - bnlen;
        tsize = bnlen;
    }
    target.insert(target.end(), (byte_t*)&value + toffset, (byte_t*)&value + toffset + tsize);
    return ret;
}

/**
 * @brief   append
 *          bin.clear();
 *          uint128 ui128 = t_htoi<uint128>("0123456789abcdef");
 *          binary_append2(bin, 8, ui128, hton128); // append
 *          // 00000000 : 01 23 45 67 89 AB CD EF -- -- -- -- -- -- -- -- | .#Eg....
 */
return_t binary_append2(binary_t& target, uint32 len, int16 value, std::function<int16(int16)> func = nullptr);
return_t binary_append2(binary_t& target, uint32 len, uint16 value, std::function<uint16(uint16)> func = nullptr);
return_t binary_append2(binary_t& target, uint32 len, int32 value, std::function<int32(int32)> func = nullptr);
return_t binary_append2(binary_t& target, uint32 len, uint32 value, std::function<uint32(uint32)> func = nullptr);
return_t binary_append2(binary_t& target, uint32 len, int64 value, std::function<int64(int64)> func = nullptr);
return_t binary_append2(binary_t& target, uint32 len, uint64 value, std::function<uint64(uint64)> func = nullptr);
#if defined __SIZEOF_INT128__
return_t binary_append2(binary_t& target, uint32 len, int128 value, std::function<int128(int128)> func = nullptr);
return_t binary_append2(binary_t& target, uint32 len, uint128 value, std::function<uint128(uint128)> func = nullptr);
#endif

/**
 * @brief   overwrite (resize and fill)
 */
template <typename T>
return_t t_binary_load(binary_t& target, uint32 bnlen, T value, std::function<T(T)> func = nullptr) {
    return_t ret = errorcode_t::success;
    target.clear();
    target.resize(bnlen);
    if (bnlen) {
        uint32 tsize = sizeof(T);
        size_t toffset = 0;
        if (func) {
            T temp = value;
            value = func(temp);
        }
        if (bnlen >= tsize) {
            //
        } else {
            toffset = tsize - bnlen;
            tsize = bnlen;
        }

        memcpy(&target[0] + (bnlen - tsize), (byte_t*)&value + toffset, tsize);
    }
    return ret;
}

return_t binary_load(binary_t& target, uint32 limit, int16 value, std::function<int16(int16)> func = nullptr);
return_t binary_load(binary_t& target, uint32 limit, uint16 value, std::function<uint16(uint16)> func = nullptr);
return_t binary_load(binary_t& target, uint32 limit, int32 value, std::function<int32(int32)> func = nullptr);
return_t binary_load(binary_t& target, uint32 limit, uint32 value, std::function<uint32(uint32)> func = nullptr);
return_t binary_load(binary_t& target, uint32 limit, int64 value, std::function<int64(int64)> func = nullptr);
return_t binary_load(binary_t& target, uint32 limit, uint64 value, std::function<uint64(uint64)> func = nullptr);
#if defined __SIZEOF_INT128__
return_t binary_load(binary_t& target, uint32 limit, int128 value, std::function<int128(int128)> func = nullptr);
return_t binary_load(binary_t& target, uint32 limit, uint128 value, std::function<uint128(uint128)> func = nullptr);
#endif
return_t binary_load(binary_t& target, uint32 limit, const byte_t* data, uint32 len);
return_t binary_fill(binary_t& target, size_t count, const byte_t& value);

/**
 * @brief append
 * @param binary_t& lhs [inout]
 * @param char* rhs [in]
 */
static inline binary_t& operator<<(binary_t& lhs, char* rhs) {
    if (rhs) {
        lhs.insert(lhs.end(), rhs, rhs + strlen(rhs));
    }
    return lhs;
}

/**
 * @brief append
 * @param binary_t& lhs [inout]
 * @param std::string rhs [in]
 */
static inline binary_t& operator<<(binary_t& lhs, const std::string& rhs) {
    lhs.insert(lhs.end(), rhs.begin(), rhs.end());
    return lhs;
}

/**
 * @brief append
 * @param binary_t& lhs [inout]
 * @param binary_t rhs [in]
 */
static inline binary_t& operator<<(binary_t& lhs, const binary_t& rhs) {
    lhs.insert(lhs.end(), rhs.begin(), rhs.end());
    return lhs;
}

/**
 * @brief   util
 */
static inline std::string bin2str(const binary_t& bin) {
    std::string result;
    if (bin.size()) {
        result.assign((char*)&bin[0], bin.size());
    }
    return result;
}

/**
 * @brief   util
 */
static inline binary_t str2bin(const std::string& source) {
    binary_t result;

    result.insert(result.end(), source.begin(), source.end());
    return result;
}

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
    if (bstr) {
        size_t tsize = sizeof(T);
        if (tsize <= size) {
            value = *(T*)bstr;
            if (tsize > 1) {
                value = convert_endian(value);  // host endian
            }
        } else {
            binary_t bin;
            binary_load(bin, tsize, bstr, size);
            value = *(T*)&bin[0];
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
    return t_binary_to_integer<T>(bin.empty() ? nullptr : &bin[0], bin.size(), errorcode);
}

template <typename T>
T t_binary_to_integer(const binary_t& bin) {
    return_t errorcode = errorcode_t::success;
    return t_binary_to_integer<T>(bin, errorcode);
}

}  // namespace hotplace

#endif
