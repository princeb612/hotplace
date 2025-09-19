/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/io/system/winpe.hpp>

namespace hotplace {
namespace io {

winpe_checksum::winpe_checksum() : _checksum(0), _size(0) {}

winpe_checksum::~winpe_checksum() {}

return_t winpe_checksum::init() {
    return_t ret = errorcode_t::success;

    _checksum = 0;
    _size = 0;

    return ret;
}

return_t winpe_checksum::update(byte_t* data, size_t bytelen) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == data) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        size_t wordlen = bytelen >> 1;
        _size += bytelen;

        for (size_t i = 0; i < wordlen; i++) {
            uint16 part = *((uint16*)data + i);
            _checksum += part;
            _checksum = (_checksum >> 16) + (_checksum & 0xffff);
        }
    }
    __finally2 {}

    return ret;
}

return_t winpe_checksum::finalize(uint32& checksum) {
    return_t ret = errorcode_t::success;

    checksum = 0;
    checksum = (uint16)(((_checksum >> 16) + _checksum) & 0xffff);
    checksum += _size;

    return ret;
}

}  // namespace io
}  // namespace hotplace
