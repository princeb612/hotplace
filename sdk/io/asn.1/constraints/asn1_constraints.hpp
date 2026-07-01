/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_constraints.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * see README.md
 */

#ifndef __HOTPLACE_SDK_IO_ASN1_CONSTRAINTS_ASN1CONSTRAINTS__
#define __HOTPLACE_SDK_IO_ASN1_CONSTRAINTS_ASN1CONSTRAINTS__

#include <hotplace/sdk/io/asn.1/constraints/types.hpp>

namespace hotplace {
namespace io {

/**
 * ITU-T X.682 ISO/IEC 8824-3
 */
class asn1_constraints {
   public:
    asn1_constraints() = default;
    asn1_constraints(const asn1_constraints& other);
    asn1_constraints(asn1_constraints&& other);
    virtual ~asn1_constraints() = default;

    asn1_constraints& operator=(const asn1_constraints& other);
    asn1_constraints& operator=(asn1_constraints&& other);

    asn1_constraints& add(asn1_constraint* cons, std::function<void(asn1_constraint*)> f = nullptr);

    void represent(stream_t* s, asn1_object* object, asn1_value* value);

    return_t validate(asn1_object* object, const variant& v);

    void addref();
    void release();

   protected:
   private:
    std::list<asn1_constraint*> _constraints;
};

}  // namespace io
}  // namespace hotplace

#endif
