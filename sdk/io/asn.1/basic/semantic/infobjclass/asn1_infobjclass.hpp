/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_infobjclass.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * see README.md
 */

#ifndef __HOTPLACE_SDK_IO_ASN1_BASIC_SEMANTIC_ASN1INFOBJCLASS__
#define __HOTPLACE_SDK_IO_ASN1_BASIC_SEMANTIC_ASN1INFOBJCLASS__

#include <hotplace/sdk/base/system/shared_instance.hpp>
#include <hotplace/sdk/io/asn.1/basic/semantic/types.hpp>

namespace hotplace {
namespace io {

// status TODO

class asn1_infobjclass {
   public:
    asn1_infobjclass();
    ~asn1_infobjclass();

    void addref();
    void release();

   protected:
   private:
    t_shared_reference<asn1_infobjclass> _shared;
};

}  // namespace io
}  // namespace hotplace

#endif
