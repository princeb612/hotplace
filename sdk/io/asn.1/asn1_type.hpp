/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_type.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * see README.md
 */

#ifndef __HOTPLACE_SDK_IO_ASN1_ASN1TYPE__
#define __HOTPLACE_SDK_IO_ASN1_ASN1TYPE__

#include <hotplace/sdk/io/asn.1/asn1_object.hpp>

namespace hotplace {
namespace io {

class asn1_type : public asn1_object {
    friend class asn1_builtin_type;
    friend class asn1_referenced_type;
    friend class asn1_tagged_type;
    friend class asn1_container;

   public:
    virtual ~asn1_type();

   protected:
    asn1_type(asn1_entity_t entity, const std::string& name = "", asn1_object* object = nullptr, asn1_tag* tag = nullptr);
};

}  // namespace io
}  // namespace hotplace

#endif
