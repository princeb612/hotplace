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
     *          auto runtime = rtcontext->current();
     */
    static return_t load_file(const char* asn1file);
    /**
     * @examples
     *          // sketch
     *          auto rtcontext = asn1_runtime_context::get_instance();
     *          loader.load_file(asn1stream, asn1size);
     *          auto runtime = rtcontext->current();
     */
    static return_t load(const char* asn1, size_t size);
};

}  // namespace io
}  // namespace hotplace

#endif
