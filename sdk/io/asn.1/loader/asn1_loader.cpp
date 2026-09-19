/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_loader.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 */

#include <hotplace/sdk/io/asn.1/loader/asn1_loader.hpp>
#include <hotplace/sdk/io/parser/lexical_analyzer.hpp>
#include <hotplace/sdk/io/stream/file_stream.hpp>

namespace hotplace {
namespace io {

asn1_loader::asn1_loader() {}

asn1_loader::~asn1_loader() {}

return_t asn1_loader::load_file(const char* asn1file, std::string& name) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == asn1file) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        file_stream fs;
        ret = fs.open(asn1file);
        if (errorcode_t::success != ret) {
            __leave2;
        }
        ret = fs.begin_mmap();
        if (errorcode_t::success != ret) {
            __leave2;
        }
        ret = load((char*)fs.data(), fs.size(), name);
    }
    __finally2 {}
    return ret;
}

return_t asn1_loader::load(const char* asn1, size_t size, std::string& name) {
    return_t ret = errorcode_t::success;
    return ret;
}

}  // namespace io
}  // namespace hotplace
