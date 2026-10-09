/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_loader.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 */

#ifndef __HOTPLACE_SDK_IO_ASN1_LOADER_ASN1LOADER__
#define __HOTPLACE_SDK_IO_ASN1_LOADER_ASN1LOADER__

#include <hotplace/sdk/io/asn.1/basic/types.hpp>
#include <hotplace/sdk/io/asn.1/runtime/types.hpp>
#include <hotplace/sdk/io/parser/types.hpp>

namespace hotplace {
namespace io {

class asn1_loader {
   public:
    asn1_loader();
    ~asn1_loader();

    /**
     * @param   const char* asn1file [in]
     * @param   parse_tree* pt [out]
     * @examples
     *          // sketch
     *          auto rtcontext = asn1_module_context::get_instance();
     *          loader.load_file("userprofile.asn1");
     */
    return_t load_file(const char* asn1file, parse_tree* pt);
    /**
     * @param   const char* asn1 [in]
     * @param   size_t size [in]
     * @param   parse_tree* pt [out]
     * @examples
     *          // sketch
     *          auto rtcontext = asn1_module_context::get_instance();
     *          loader.load_file(asn1stream, asn1size);
     */
    return_t load(const char* asn1, size_t size, parse_tree* pt);

    return_t asn1file_to_tokens(asn1_parser* parser, const char* asn1file, std::vector<parser_token>& tokens);
    return_t asn1_to_tokens(asn1_parser* parser, const char* asn1, size_t size, std::vector<parser_token>& tokens);
};

}  // namespace io
}  // namespace hotplace

#endif
