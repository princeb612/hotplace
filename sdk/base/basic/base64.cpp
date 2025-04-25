/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *  RFC 4648 The Base16, Base32, and Base64 Data Encodings
 *
 * Revision History
 * Date         Name                Description
 * 2023.08.16   Soo Han, Kim        fix : base64_encode encoded size
 * 2023.08.20   Soo Han, Kim        fix : base64_encode source access range
 */

#include <sdk/base/basic/base64.hpp>

namespace hotplace {

/*
    BASE64
        + /
        = padding
    BASE64URL
        - _
        no padding
 */

static const byte_t MIME_BASE64_ENCODE[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V',
                                            'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r',
                                            's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'};

static const byte_t MIME_BASE64URL_ENCODE[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V',
                                               'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r',
                                               's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '-', '_'};

/* +(0x2B) to 62, /(0x2F) to 63 */
static const int MIME_BASE64_DECODE[256] = {
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /* 00-0F */
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /* 10-1F */
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, -1, 63, /* 20-2F */
    52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1, /* 30-3F */
    -1, 0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14, /* 40-4F */
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1, /* 50-5F */
    -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, /* 60-6F */
    41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1, /* 70-7F */
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /* 80-8F */
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /* 90-9F */
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /* A0-AF */
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /* B0-BF */
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /* C0-CF */
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /* D0-DF */
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /* E0-EF */
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1  /* F0-FF */
};

/* -(0x2D) to 62, _(0x5F) to 63 */
static const int MIME_BASE64URL_DECODE[256] = {
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /* 00-0F */
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /* 10-1F */
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, /* 20-2F */
    52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1, /* 30-3F */
    -1, 0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14, /* 40-4F */
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, 63, /* 50-5F */
    -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, /* 60-6F */
    41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1, /* 70-7F */
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /* 80-8F */
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /* 90-9F */
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /* A0-AF */
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /* B0-BF */
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /* C0-CF */
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /* D0-DF */
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /* E0-EF */
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1  /* F0-FF */
};

typedef union {
    struct {
        unsigned char c1, c2, c3;
    };
    struct {
        unsigned int e1 : 6, e2 : 6, e3 : 6, e4 : 6;
    };
    uint32 i32;
} base64_conv_t;

return_t base64_encode(const byte_t* source, size_t source_size, byte_t* buffer, size_t* buffer_size, int encoding) {
    return_t ret = errorcode_t::success;
    size_t i = 0, j = 0;
    base64_conv_t temp;

    __try2 {
        if (nullptr == source || nullptr == buffer_size) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        if (0 == source_size) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        // #check.1 source 3bytes to encoded 4bytes
        // 3bytes (8bits,8bits,8bits) : 2^8 (ASCII table)
        // 4bytes (6bits,6bits,6bits,6bits) : 2^6 = 64 (BASE64 table)
        //
        // #check.2 switch source_size, n >= 0
        // pattern 3n+1 : enclen = (source_size/3 * 4) + 2; pad = "=="; (+2 + "==" -> 4)
        // pattern 3n+2 : enclen = (source_size/3 * 4) + 3; pad = "=";  (+3 + "="  -> 4)
        // pattern 3n+3 : enclen = (source_size/3 * 4) + 0; pad = n/a;  (+4 + ""   -> 4)
        //
        // #check.3 srclen , enclen ('=') padded , size not padded
        // 1 => 4, 2; 2 => 4, 3; 3 => 4, 4
        // 4 => 8, 6; 5 => 8, 7; 6 => 8, 8
        // 7 => 12, 10; 8 => 12, 11; 9 => 12, 12

        const byte_t* table = MIME_BASE64_ENCODE;
        if (encoding_t::encoding_base64url == encoding) {
            // RFC 7515 Appendix C.  Notes on Implementing base64url Encoding without Padding
            table = MIME_BASE64URL_ENCODE;
        }

        size_t size_need = (4 * (source_size / 3)) + (source_size % 3 ? 4 : 0);

        if (*buffer_size < size_need) {
            *buffer_size = size_need;

            ret = errorcode_t::insufficient_buffer;
            __leave2;
        }
        if (nullptr == buffer) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        for (i = 0; i < source_size; i += 3, j += 4) {
            temp.i32 = 0;
            temp.c3 = source[i];
            if ((i + 1) < source_size) {
                temp.c2 = source[i + 1];
            }
            if ((i + 2) < source_size) {
                temp.c1 = source[i + 2];
            }

            buffer[j] = table[temp.e4];
            buffer[j + 1] = table[temp.e3];
            buffer[j + 2] = table[temp.e2];
            buffer[j + 3] = table[temp.e1];

            // RFC 7515 Appendix C.  Notes on Implementing base64url Encoding without Padding
            if (encoding_t::encoding_base64 == encoding) {
                if ((i + 2) > source_size) {
                    buffer[j + 2] = '=';
                }
                if ((i + 3) > source_size) {
                    buffer[j + 3] = '=';
                }
            }
        }

        if (encoding_t::encoding_base64url == encoding) {
            size_need = (4 * (source_size / 3)) + (source_size % 3 ? (source_size % 3) + 1 : 0);
        }

        *buffer_size = size_need;
    }
    __finally2 {
        // do nothing
    }

    return ret;
}

return_t base64_decode(const byte_t* source, size_t source_size, byte_t* buffer, size_t* buffer_size, int encoding) {
    return_t ret = errorcode_t::success;
    size_t i, j = 0;
    base64_conv_t temp;

    __try2 {
        if (nullptr == source || nullptr == buffer_size) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        // from x(n-1)+1 to x(n) -> x(n)
        // (( n + (x - 1)) / x) * x , (n > 0)
        // if x=3 then 1~3 -> 3, 4~6 -> 6
        // if x=4 then 1~4 -> 4, 5~8 -> 8

        const int* table = MIME_BASE64_DECODE;
        if (encoding_t::encoding_base64url == encoding) {
            table = MIME_BASE64URL_DECODE;
        }

        size_t size_buffer = *buffer_size;
        size_t size_need = (source_size * 3 / 4) + 2; /* trailing == */
        if (*buffer_size < size_need) {
            *buffer_size = size_need;
            ret = errorcode_t::insufficient_buffer;
            __leave2;
        }
        if (nullptr == buffer || 0 == source_size) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        while (1) {
            if ('=' == *(source + source_size - 1)) {
                source_size--;
            } else {
                break;
            }
        }

        for (i = 0; i < source_size; i = i + 4, j = j + 3) {
            temp.e4 = table[source[i]];
            temp.e3 = 0x00;
            if (i + 1 < source_size) {
                temp.e3 = table[source[i + 1]];
            }
            temp.e2 = 0x00;
            if (i + 2 < source_size) {
                if (source[i + 2] == '=') {
                    temp.e2 = 0x00;
                } else {
                    temp.e2 = table[source[i + 2]];
                }
            }
            temp.e1 = 0x00;
            if (i + 3 < source_size) {
                if (source[i + 3] == '=') {
                    temp.e1 = 0x00;
                } else {
                    temp.e1 = table[source[i + 3]];
                }
            }

            buffer[j] = temp.c3;
            if (j + 1 < size_buffer) {
                buffer[j + 1] = temp.c2;
            }
            if (j + 2 < size_buffer) {
                buffer[j + 2] = temp.c1;
            }
        }

        *buffer_size = (source_size * 3 / 4);
    }
    __finally2 {
        // do nothing
    }

    return ret;
}

return_t base64_encode(const byte_t* source, size_t source_size, binary_t& encoded, int encoding) {
    return_t ret = errorcode_t::success;

    size_t size = 0;

    base64_encode(source, source_size, &encoded[0], &size, encoding);
    encoded.resize(size);
    ret = base64_encode(source, source_size, &encoded[0], &size, encoding);
    encoded.resize(size);

    return ret;
}

return_t base64_encode(const byte_t* source, size_t source_size, std::string& encoded, int encoding) {
    return_t ret = errorcode_t::success;

    size_t size = 0;

    base64_encode(source, source_size, (byte_t*)&encoded[0], &size, encoding);
    encoded.resize(size);
    base64_encode(source, source_size, (byte_t*)&encoded[0], &size, encoding);
    encoded.resize(size);

    return ret;
}

std::string base64_encode(const byte_t* source, size_t source_size, int encoding) {
    std::string encoded;

    size_t size = 0;

    base64_encode(source, source_size, (byte_t*)&encoded[0], &size, encoding);
    encoded.resize(size);
    base64_encode(source, source_size, (byte_t*)&encoded[0], &size, encoding);
    encoded.resize(size);
    return encoded;
}

std::string base64_encode(const binary_t& source, int encoding) { return base64_encode(&source[0], source.size(), encoding); }

std::string base64_encode(const std::string& source, int encoding) { return base64_encode((byte_t*)source.c_str(), source.size(), encoding); }

return_t base64_decode(const char* source, size_t source_size, binary_t& decoded, int encoding) {
    return_t ret = errorcode_t::success;

    size_t size = 0;

    base64_decode((byte_t*)source, source_size, &decoded[0], &size, encoding);
    decoded.resize(size);
    base64_decode((byte_t*)source, source_size, &decoded[0], &size, encoding);
    decoded.resize(size);

    return ret;
}

return_t base64_decode(const std::string& source, binary_t& decoded, int encoding) {
    return_t ret = errorcode_t::success;

    size_t size = 0;

    base64_decode((byte_t*)source.c_str(), source.size(), &decoded[0], &size, encoding);
    decoded.resize(size);
    base64_decode((byte_t*)source.c_str(), source.size(), &decoded[0], &size, encoding);
    decoded.resize(size);

    return ret;
}

binary_t base64_decode(const char* source, size_t source_size, int encoding) {
    binary_t decoded;

    base64_decode(source, source_size, decoded, encoding);
    return decoded;
}

binary_t base64_decode(const binary_t& source, int encoding) { return base64_decode((char*)&source[0], source.size(), encoding); }

binary_t base64_decode(const std::string& source, int encoding) { return base64_decode(source.c_str(), source.size(), encoding); }

std::string base64_decode_careful(const std::string& source, int encoding) { return base64_decode_careful(source.c_str(), source.size(), encoding); }

std::string base64_decode_careful(const char* source, size_t source_size, int encoding) {
    std::string decoded;
    size_t size = 0;

    base64_decode((byte_t*)source, source_size, (byte_t*)&decoded[0], &size, encoding);
    decoded.resize(size);
    base64_decode((byte_t*)source, source_size, (byte_t*)&decoded[0], &size, encoding);
    decoded.resize(size);
    return decoded;
}

}  // namespace hotplace
