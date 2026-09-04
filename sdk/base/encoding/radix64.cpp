/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   radix64.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 * 2020.02.06   Soo Han, Kim        codename.unicorn Revision 49
 * 2026.09.04   Soo Han, Kim        codename.hotplace Revision 1070
 *
 */

#include <hotplace/sdk/base/encoding/base64.hpp>
#include <hotplace/sdk/base/system/endian.hpp>

namespace hotplace {

#define CRC24_INIT 0xB704CEL
#define CRC24_POLY 0x1864CFBL

uint32 crc24(const unsigned char* octets, size_t len) {
    uint32 crc = CRC24_INIT;
    if (octets && len) {
        int i = 0;
        while (len--) {
            crc ^= (*octets++) << 16;
            for (i = 0; i < 8; i++) {
                crc <<= 1;
                if (crc & 0x1000000) {
                    crc ^= CRC24_POLY;
                }
            }
        }
    }
    return crc & 0xFFFFFFL;
}

return_t radix64_armor_encode(const byte_t* data, size_t data_size, std::string& encoded, std::string& crc) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == data) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        ret = base64_encode(data, data_size, encoded);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        auto checksum = hton32(crc24(data, data_size));
        ret = base64_encode((byte_t*)&checksum + 1, 3, crc);
    }
    __finally2 {}
    return ret;
}

return_t radix64_armor_decode(const char* encoded, size_t encoded_size, const char* armor, size_t armor_size, binary_t& decoded) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == encoded || nullptr == armor) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        ret = base64_decode(encoded, encoded_size, decoded);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        std::string source_crc;
        auto checksum = hton32(crc24(decoded.data(), decoded.size()));
        ret = base64_encode((byte_t*)&checksum + 1, 3, source_crc);
        if (errorcode_t::success != ret) {
            __leave2;
        }
        if (armor_size == source_crc.size() && 0 == memcmp(source_crc.c_str(), armor, armor_size)) {
            // do nothing
        } else {
            ret = errorcode_t::mismatch;
        }
    }
    __finally2 {}
    return ret;
}

}  // namespace hotplace
