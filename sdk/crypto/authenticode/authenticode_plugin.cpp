/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/crypto/authenticode/authenticode_plugin.hpp>

namespace hotplace {
namespace crypto {

authenticode_plugin::authenticode_plugin() { _shared.make_share(this); }

authenticode_plugin::~authenticode_plugin() {
    // do nothing
}

return_t authenticode_plugin::extract(file_stream* filestream, binary_t& bin) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == filestream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        ret = read_authenticode(filestream, bin);
        if (errorcode_t::success != ret) {
            __leave2;
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

int authenticode_plugin::addref() { return _shared.addref(); }

int authenticode_plugin::release() { return _shared.delref(); }

}  // namespace crypto
}  // namespace hotplace
