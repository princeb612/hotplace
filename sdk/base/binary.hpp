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

#include <functional>
#include <map>
#include <sdk/base/error.hpp>
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

static inline std::string convert(const binary_t& bin) {
    std::string result;

    result.assign((char*)&bin[0], bin.size());
    return result;
}

static inline binary_t convert(const std::string& source) {
    binary_t result;

    result.insert(result.end(), source.begin(), source.end());
    return result;
}

}  // namespace hotplace

#endif
