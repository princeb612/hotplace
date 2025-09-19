/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * see README.md
 */

#ifndef __HOTPLACE_SDK_IO_ASN1_ASN1SET__
#define __HOTPLACE_SDK_IO_ASN1_ASN1SET__

#include <hotplace/sdk/io/asn.1/asn1_container.hpp>

namespace hotplace {
namespace io {

/**
 * @brief   SetType
 * @sample
 *      ChildInformation ::= SET {name Name, dateOfBirth [0] Date}
 *
 *      asn1_set* node_childinfo = new asn1_set("ChildInformation");
 *      *node_childinfo << new asn1_namedtype("name", new asn1_referenced_type("Name"))
 *                      << new asn1_namedtype("dateOfBirth", new asn1_referenced_type("Date", new asn1_tag(0)));
 *      node_childinfo->release();
 */
class asn1_set : public asn1_container {
   public:
    asn1_set(asn1_tag* tag = nullptr);
    asn1_set(const std::string& name, asn1_tag* tag = nullptr);
    asn1_set(const asn1_set& rhs);

    asn1_object* clone();

    virtual void represent(binary_t* b);

   protected:
};

/**
 * @brief   SetOfType ::= SET OF Type | SET OF NamedType
 */
class asn1_set_of : public asn1_container {
   public:
    asn1_set_of(asn1_tag* tag = nullptr);
    asn1_set_of(const std::string& name, asn1_tag* tag = nullptr);
    asn1_set_of(const asn1_set_of& rhs);

    asn1_object* clone();

    virtual void represent(binary_t* b);

   protected:
};

}  // namespace io
}  // namespace hotplace

#endif
