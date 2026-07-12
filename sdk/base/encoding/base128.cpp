/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   base128.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 */

#include <hotplace/sdk/base/encoding/base128.hpp>

namespace hotplace {

return_t base128_encode(uint64 value, binary_t& bin) {
    size_t count = 1;
    uint64 tmp = value;
    while (tmp >>= 7) ++count;

    size_t pos = bin.size();
    bin.resize(pos + count);

    for (size_t i = count; i > 0; --i) {
        byte_t b = value & 0x7f;
        value >>= 7;

        if (i != count) b |= 0x80;

        bin[pos + i - 1] = b;
    }

    return errorcode_t::success;
}

// Gemini prototyped - fuzzing guard
return_t base128_decode(const byte_t* stream, size_t size, size_t& pos, uint64& value) {
    value = 0;
    size_t byte_count = 0;

    while (pos < size) {
        byte_t b = stream[pos++];
        byte_count++;

        if (byte_count == 1 && b == 0x80) {
            return errorcode_t::bad_format;
        }

        if (byte_count > 9) {
            if (byte_count > 10 || (value > (0xFFFFFFFFFFFFFFFFULL >> 7))) {
                return errorcode_t::bad_format;
            }
        }

        value = (value << 7) | (b & 0x7f);

        if ((b & 0x80) == 0) {
            return errorcode_t::success;
        }
    }

    return errorcode_t::bad_data;
}

return_t base128_encode(const byte_t* stream, size_t size, binary_t& bin) {
    if (nullptr == stream || 0 == size) return errorcode_t::invalid_parameter;
    bignumber bn(stream, size);
    return base128_encode(bn, bin);
}

return_t base128_decode(const byte_t* stream, size_t size, size_t& pos, binary_t& value) {
    if (nullptr == stream || 0 == size) return errorcode_t::invalid_parameter;

    value.clear();

    bignumber bn;
    auto test = base128_decode(stream, size, pos, bn);
    bn.get(value);
    return test;
}

return_t base128_encode(const bignumber& value, binary_t& bin) {
    size_t count = 1;
    bignumber tmp = value;
    while (tmp >>= 7) ++count;

    size_t pos = bin.size();
    bin.resize(pos + count);
    tmp = value;

    for (size_t i = count; i > 0; --i) {
        byte_t b = (uint8)tmp & 0x7f;
        tmp >>= 7;

        if (i != count) b |= 0x80;

        bin[pos + i - 1] = b;
    }

    return errorcode_t::success;
}

return_t base128_decode(const binary_t& bin, bignumber& value) {
    size_t pos = 0;
    return base128_decode(bin.data(), bin.size(), pos, value);
}

return_t base128_decode(const byte_t* stream, size_t size, size_t& pos, bignumber& value) {
    if (nullptr == stream || 0 == size) return errorcode_t::invalid_parameter;

    value = 0;
    size_t byte_count = 0;
    const size_t MAX_BASE128_BYTES = 1024;  // Fuzzing guard

    while (pos < size) {
        if (byte_count >= MAX_BASE128_BYTES) return errorcode_t::bad_format;

        byte_t b = stream[pos++];
        byte_count++;

        if (byte_count == 1 && b == 0x80) return errorcode_t::bad_format;

        // value = (value * 128) + (b & 0x7f)
        value *= 128;
        value += (b & 0x7F);

        if ((b & 0x80) == 0) return errorcode_t::success;
    }

    return errorcode_t::bad_data;  // stream broken
}

}  // namespace hotplace
