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
     * @examples
     *          // sketch
     *          auto rtcontext = asn1_runtime_context::get_instance();
     *          loader.load_file("userprofile.asn1");
     */
    static return_t load_file(const char* asn1file, parse_tree* pt);
    /**
     * @examples
     *          // sketch
     *          auto rtcontext = asn1_runtime_context::get_instance();
     *          loader.load_file(asn1stream, asn1size);
     */
    static return_t load(const char* asn1, size_t size, parse_tree* pt);

   private:
    std::vector<std::string> _module_names;
};

}  // namespace io
}  // namespace hotplace

#endif
