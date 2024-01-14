/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/base/stream/basic_stream.hpp>
#include <sdk/base/system/datetime.hpp>
#include <sdk/crypto/basic/openssl_prng.hpp>
#include <sdk/io/system/types.hpp>

namespace hotplace {
using namespace io;
namespace crypto {

openssl_prng::openssl_prng() {
    // do nothing
}

openssl_prng::~openssl_prng() {
    // do nothing
}

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
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t openssl_prng::random(binary_t& buffer, size_t size) {
    return_t ret = errorcode_t::success;

    buffer.resize(size);
    RAND_bytes(&buffer[0], buffer.size());
    return ret;
}

return_t openssl_prng::random(uint32& i, uint32 mask) {
    return_t ret = errorcode_t::success;

    RAND_bytes((byte_t*)&i, sizeof(i));
    i &= mask;
    return ret;
}

std::string openssl_prng::nonce(size_t size) {
    std::string ret_value;

    if (size < 8) {
        size = 8;
    }

    binary_t buffer;
    buffer.resize(size);
    RAND_bytes(&buffer[0], buffer.size());
    base16_encode(buffer, ret_value);

    return ret_value;
}

std::string openssl_prng::token(size_t size) {
    std::string ret_value;

    if (size < 8) {
        size = 8;
    }

    datetime dt;
    basic_stream bs;

    struct timespec ts = {
        0,
    };
    dt.gettimespec(&ts);
    uint64 sec = hton64(ts.tv_sec);
    base16_encode((byte_t*)&sec, sizeof(sec), ret_value);

    binary_t buffer;
    buffer.resize(size);
    RAND_bytes(&buffer[0], buffer.size());
    ret_value += base64_encode(buffer, base64_encoding_t::base64url_encoding);

    return ret_value;
}

}  // namespace crypto
}  // namespace hotplace
