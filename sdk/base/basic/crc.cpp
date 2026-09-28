/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   crc.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/base/basic/crc.hpp>

namespace hotplace {

// CRC32 calculation helper (IEEE 802.3 standard polynomial 0xEDB88320)
uint32 crc32(const unsigned char* octets, size_t len) {
    uint32 crc = 0xFFFFFFFF;
    for (size_t i = 0; i < len; ++i) {
        crc ^= octets[i];
        for (int j = 0; j < 8; ++j) {
            crc = (crc >> 1) ^ (0xEDB88320 & -(crc & 1));
        }
    }
    return ~crc;
}

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

}  // namespace hotplace
