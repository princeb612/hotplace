/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_object_class.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * see README.md
 */

#ifndef __HOTPLACE_SDK_IO_ASN1_ASN1OBJECTCLASS__
#define __HOTPLACE_SDK_IO_ASN1_ASN1OBJECTCLASS__

#include <hotplace/sdk/base/basic/variant.hpp>
#include <hotplace/sdk/base/system/shared_instance.hpp>
#include <hotplace/sdk/io/asn.1/types.hpp>

namespace hotplace {
namespace io {

class asn1_object_class {
   public:
    asn1_object_class();
    ~asn1_object_class();

    void addref();
    void release();

   protected:
   private:
    t_shared_reference<asn1_object_class> _shared;
};

}  // namespace io
}  // namespace hotplace

#endif
