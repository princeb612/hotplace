/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * see README.md
 */

#ifndef __HOTPLACE_SDK_IO_ASN1_TEMPLATE__
#define __HOTPLACE_SDK_IO_ASN1_TEMPLATE__

#include <sdk/base/inline.hpp>
#include <sdk/base/template.hpp>
#include <sdk/io/asn.1/asn1.hpp>
#include <sdk/io/asn.1/types.hpp>
#include <sdk/io/basic/parser.hpp>

namespace hotplace {
namespace io {

/**
 * @brief   length octets
 * @sa
 *          X.690 8.1.3 Length octets
 */
template <typename type>
uint32 t_asn1_length_octets(binary_t& bin, type len, size_t pos = -1) {
    if (-1 == pos) {
        pos = bin.size();
    }

    uint32 size_encode = 0;
    if (len > 0x7f) {
        int bytesize = byte_capacity(len);
        type temp = convert_endian(len);
        bin.insert(bin.begin() + pos, 0x80 | bytesize);  // X.690 8.1.3.5
        bin.insert(bin.begin() + pos + 1, (byte_t*)&temp + sizeof(type) - bytesize, (byte_t*)&temp + sizeof(type));
        size_encode = 1 + bytesize;
    } else {
        // X.690 8.1.3.4
        bin.insert(bin.begin() + pos, (byte_t)len);
        size_encode = 1;
    }
    return size_encode;
}

// X.690 8.19.2
template <typename type>
size_t t_asn1_oid_value(binary_t& bin, type v, size_t pos = -1) {
    if (-1 == pos) {
        pos = bin.size();
    }
    size_t len = 0;
    uint8 m = 0;
    while (v > 0x7f) {
        bin.insert(bin.begin() + pos, ((byte_t)v & 0x7f) | m);
        v >>= 7;
        m = 0x80;
        len++;
    }
    bin.insert(bin.begin() + pos, v | m);
    return len + 1;
}

template <typename type>
uint32 t_asn1_encode_integer_value(binary_t& bin, type v, size_t pos = -1) {
    if (-1 == pos) {
        pos = bin.size();
    }
    uint32 len = byte_capacity(v);
    type temp = convert_endian(v);
    bin.insert(bin.begin() + pos, (byte_t*)&temp + sizeof(type) - len, (byte_t*)&temp + sizeof(type));
    return len;
}

}  // namespace io
}  // namespace hotplace

#endif
