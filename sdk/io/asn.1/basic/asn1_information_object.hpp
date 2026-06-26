/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_information_object.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * see README.md
 */

#ifndef __HOTPLACE_SDK_IO_ASN1_ASN1INFORMATIONOBJECT__
#define __HOTPLACE_SDK_IO_ASN1_ASN1INFORMATIONOBJECT__

#include <hotplace/sdk/base/basic/variant.hpp>
#include <hotplace/sdk/base/system/shared_instance.hpp>
#include <hotplace/sdk/io/asn.1/types.hpp>

namespace hotplace {
namespace io {

class asn1_information_object {
   public:
    asn1_information_object();
    ~asn1_information_object();

    void addref();
    void release();

   protected:
   private:
    t_shared_reference<asn1_information_object> _shared;
};

}  // namespace io
}  // namespace hotplace

#endif
