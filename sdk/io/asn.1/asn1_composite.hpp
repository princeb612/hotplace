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

#ifndef __HOTPLACE_SDK_IO_ASN1_ASN1COMPOSITE__
#define __HOTPLACE_SDK_IO_ASN1_ASN1COMPOSITE__

#include <sdk/io/asn.1/asn1_object.hpp>

namespace hotplace {
namespace io {

class asn1_composite : public asn1_object {
   public:
    /**
     * asn1_type_t type MUST be asn1_type_primitive or asn1_type_constructed
     */
    asn1_composite(asn1_type_t type, asn1_object* obj, asn1_tag* tag = nullptr);
    asn1_composite(const asn1_composite& rhs);
    virtual ~asn1_composite();

    virtual asn1_object* clone();

    asn1_composite& as_primitive();
    asn1_composite& as_constructed();

    virtual void represent(stream_t* s);
    virtual void represent(binary_t* b);

    asn1_object* get_object();

   protected:
    void clear();

   private:
    asn1_object* _object;
};

}  // namespace io
}  // namespace hotplace

#endif
