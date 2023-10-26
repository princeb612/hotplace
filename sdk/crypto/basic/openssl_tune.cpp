/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/crypto/basic/crypto_advisor.hpp>
#include <sdk/crypto/basic/openssl_sdk.hpp>
#include <sdk/io/string/string.hpp>

namespace hotplace {
using namespace io;
namespace crypto {

static uint32 ossl_cooltime = 0;
static uint32 ossl_cooltime_max = 1000;
static uint32 ossl_cooltime_unitsize = 4096;

return_t ossl_set_cooltime(uint32 ms) {
    return_t ret = errorcode_t::success;

    if (ms < ossl_cooltime_max) {
        ossl_cooltime = ms;
    } else {
        ret = errorcode_t::out_of_range;
    }
    return ret;
}

return_t ossl_set_cooltime_max(uint32 ms) {
    return_t ret = errorcode_t::success;

    if (0 == ms) {
        ret = errorcode_t::invalid_parameter;
    } else if (ossl_cooltime <= ms) {
        ossl_cooltime_max = ms;
    } else {
        ret = errorcode_t::invalid_parameter;
    }
    return ret;
}

uint32 ossl_get_cooltime() { return ossl_cooltime; }

return_t ossl_set_unitsize(uint32 size) {
    return_t ret = errorcode_t::success;

    if (0 == size) {
        ret = errorcode_t::invalid_parameter;
    } else {
        ossl_cooltime_unitsize = (size + 7) & ~7;
    }
    return ret;
}

uint32 ossl_get_unitsize() {
    if (ossl_cooltime_unitsize) {
        return ossl_cooltime_unitsize;
    } else {
        return 1;  // safe coding
    }
}

}  // namespace crypto
}  // namespace hotplace
