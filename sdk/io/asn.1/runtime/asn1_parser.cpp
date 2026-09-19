/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_parser.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * see README.md
 */

#include <hotplace/sdk/base/stream/basic_stream.hpp>
#include <hotplace/sdk/base/system/trace.hpp>
#include <hotplace/sdk/io/asn.1/asn1_resource.hpp>
#include <hotplace/sdk/io/asn.1/runtime/asn1_parser.hpp>
#include <hotplace/sdk/io/asn.1/runtime/asn1_runtime.hpp>
#include <hotplace/sdk/io/parser/parser_resource.hpp>

namespace hotplace {
namespace io {

asn1_parser::asn1_parser() {}

return_t asn1_parser::parse(asn1_runtime* runtime, const char* notation, parse_tree* pt) const {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == runtime || nullptr == notation) {
            ret = errorcode_t::invalid_parameter;
        }

        ret = runtime->parse(notation, pt);
    }
    __finally2 {}
    return ret;
}

}  // namespace io
}  // namespace hotplace
