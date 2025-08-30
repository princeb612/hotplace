/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/crypto/basic/openssl_prng.hpp>

namespace hotplace {
namespace crypto {

openssl_prng::openssl_prng() {}

openssl_prng::~openssl_prng() {}

int32 openssl_prng::rand32() {
    int32 val = 0;

    RAND_bytes((unsigned char*)&val, sizeof(val));
    return val;
}

int64 openssl_prng::rand64() {
    int64 val = 0;

    RAND_bytes((unsigned char*)&val, sizeof(val));
    return val;
}

return_t openssl_prng::random(unsigned char* buf, size_t size) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == buf || 0 == size) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        RAND_bytes(buf, size);
    }
    __finally2 {}
    return ret;
}

return_t openssl_prng::random(binary_t& buffer, size_t size) {
    return_t ret = errorcode_t::success;
    if (0 == size) {
        ret = errorcode_t::do_nothing;
    } else {
        buffer.resize(size);
        RAND_bytes(&buffer[0], buffer.size());
    }
    return ret;
}

return_t openssl_prng::random(uint32& i, uint32 mask) {
    return_t ret = errorcode_t::success;

    RAND_bytes((byte_t*)&i, sizeof(i));
    i &= mask;
    return ret;
}

std::string openssl_prng::rand(size_t size, encoding_t expr, bool usetime) {
    std::string ret_value;

    if (size < 8) {
        size = 8;
    }

    if (usetime) {
        datetime dt;
        struct timespec ts = {
            0,
        };
        dt.gettimespec(&ts);
        uint64 sec = hton64(ts.tv_sec);
        if (encoding_t::encoding_base64 == expr) {
            ret_value = base64_encode((byte_t*)&sec, sizeof(sec), encoding_t::encoding_base64);
        } else if (encoding_t::encoding_base64url == expr) {
            ret_value = base64_encode((byte_t*)&sec, sizeof(sec), encoding_t::encoding_base64url);
        } else {  // encoding_t::encoding_base16
            base16_encode((byte_t*)&sec, sizeof(sec), ret_value);
        }
    }

    binary_t buffer;
    buffer.resize(size);
    RAND_bytes(&buffer[0], buffer.size());
    if (encoding_t::encoding_base64 == expr) {
        ret_value += base64_encode(buffer, encoding_t::encoding_base64);
    } else if (encoding_t::encoding_base64url == expr) {
        ret_value += base64_encode(buffer, encoding_t::encoding_base64url);
    } else {  // encoding_t::encoding_base16
        ret_value += base16_encode(buffer);
    }

    return ret_value;
}

std::string openssl_prng::nonce(size_t size, encoding_t expr) { return rand(size, expr, false); }

std::string openssl_prng::token(size_t size, encoding_t expr) { return rand(size, expr, false); }

}  // namespace crypto
}  // namespace hotplace
