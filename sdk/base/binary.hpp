/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_BASE_BINARY__
#define __HOTPLACE_SDK_BASE_BINARY__

#include <string.h>

#include <functional>
#include <sdk/base/charset.hpp>
#include <sdk/base/error.hpp>
#include <sdk/base/syntax.hpp>
#include <sdk/base/types.hpp>

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
    binary(int128 rhs);
    binary(uint128 rhs);
    binary(float rhs);
    binary(double rhs);
    binary(const std::string& rhs);
    binary(const char* rhs);
    binary(const byte_t* buf, size_t size);

    binary(const binary_t& rhs);
    binary(binary_t&& rhs);

    binary& push_back(byte_t rhs);

    /*
     * @sample
     *          uint32 data = 100;
     *          b.append(data, htonl);
     */
    binary& append(int16 rhs, std::function<int16(int16)> func = nullptr);
    binary& append(uint16 rhs, std::function<uint16(uint16)> func = nullptr);
    binary& append(int32 rhs, std::function<int32(int32)> func = nullptr);
    binary& append(uint32 rhs, std::function<uint32(uint32)> func = nullptr);
    binary& append(int64 rhs, std::function<int64(int64)> func = nullptr);
    binary& append(uint64 rhs, std::function<uint64(uint64)> func = nullptr);
    binary& append(int128 rhs, std::function<int128(int128)> func = nullptr, size_t len = sizeof(int128));
    binary& append(uint128 rhs, std::function<uint128(uint128)> func = nullptr, size_t len = sizeof(uint128));
    binary& append(float rhs, std::function<uint32(uint32)> func = nullptr);
    binary& append(double rhs, std::function<uint64(uint64)> func = nullptr);
    binary& append(const std::string& rhs);
    binary& append(const binary_t& rhs);
    binary& append(const binary& rhs);
    binary& append(const char* rhs);
    binary& append(const char* buf, size_t size);
    binary& append(const byte_t* buf, size_t size);
    binary& append(const byte_t* buf, size_t from, size_t to);

    binary& operator<<(char rhs);
    binary& operator<<(byte_t rhs);
    binary& operator<<(int16 rhs);
    binary& operator<<(uint16 rhs);
    binary& operator<<(int32 rhs);
    binary& operator<<(uint32 rhs);
    binary& operator<<(int64 rhs);
    binary& operator<<(uint64 rhs);
    binary& operator<<(int128 rhs);
    binary& operator<<(uint128 rhs);
    binary& operator<<(float rhs);
    binary& operator<<(double rhs);
    binary& operator<<(const std::string& rhs);
    binary& operator<<(const binary_t& rhs);
    binary& operator<<(const binary& rhs);
    binary& operator<<(const char* rhs);

    binary& operator=(char rhs);
    binary& operator=(byte_t rhs);
    binary& operator=(int16 rhs);
    binary& operator=(uint16 rhs);
    binary& operator=(int32 rhs);
    binary& operator=(uint32 rhs);
    binary& operator=(int64 rhs);
    binary& operator=(uint64 rhs);
    binary& operator=(int128 rhs);
    binary& operator=(uint128 rhs);
    binary& operator=(float rhs);
    binary& operator=(double rhs);
    binary& operator=(const std::string& rhs);
    binary& operator=(const binary_t& rhs);
    binary& operator=(const binary& rhs);
    binary& operator=(const char* rhs);

    binary& clear();

    binary_t& get();
    const binary_t& get() const;
    operator binary_t();
    operator const binary_t&() const;

   private:
    binary_t _bin;
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
 *          bin.clear();
 *          uint128 ui128 = t_htoi<uint128>("0123456789abcdef");
 *          binary_append(bin, ui128, hton128, 8);
 *          // 00000000 : 01 23 45 67 89 AB CD EF -- -- -- -- -- -- -- -- | .#Eg....
 */
return_t binary_push(binary_t& target, byte_t rhs);
return_t binary_append(binary_t& target, int16 rhs, std::function<int16(int16)> func = nullptr);
return_t binary_append(binary_t& target, uint16 rhs, std::function<uint16(uint16)> func = nullptr);
return_t binary_append(binary_t& target, int32 rhs, std::function<int32(int32)> func = nullptr);
return_t binary_append(binary_t& target, uint32 rhs, std::function<uint32(uint32)> func = nullptr);
return_t binary_append(binary_t& target, int64 rhs, std::function<int64(int64)> func = nullptr);
return_t binary_append(binary_t& target, uint64 rhs, std::function<uint64(uint64)> func = nullptr);
return_t binary_append(binary_t& target, int128 rhs, std::function<int128(int128)> func = nullptr, size_t len = sizeof(int128));
return_t binary_append(binary_t& target, uint128 rhs, std::function<uint128(uint128)> func = nullptr, size_t len = sizeof(uint128));
return_t binary_append(binary_t& target, float rhs, std::function<uint32(uint32)> func = nullptr);
return_t binary_append(binary_t& target, double rhs, std::function<uint64(uint64)> func = nullptr);
return_t binary_append(binary_t& target, const std::string& rhs);
return_t binary_append(binary_t& target, const binary_t& rhs);
return_t binary_append(binary_t& target, const binary& rhs);
return_t binary_append(binary_t& target, const char* rhs);
return_t binary_append(binary_t& target, const char* buf, size_t size);
return_t binary_append(binary_t& target, const byte_t* buf, size_t size);
return_t binary_append(binary_t& target, const byte_t* buf, size_t from, size_t to);
return_t binary_load(binary_t& bn, uint32 bnlen, byte_t* data, uint32 len);

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

    result.assign((char*)&bin[0], bin.size());
    return result;
}

/**
 * @brief   util
 */
static inline binary_t strtobin(const std::string& source) {
    binary_t result;

    result.insert(result.end(), source.begin(), source.end());
    return result;
}

}  // namespace hotplace

#endif
