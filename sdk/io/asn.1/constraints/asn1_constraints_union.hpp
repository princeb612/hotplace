/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_constraints_union.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * see README.md
 */

#ifndef __HOTPLACE_SDK_IO_ASN1_CONSTRAINTS_ASN1CONSTRAINTSUNION__
#define __HOTPLACE_SDK_IO_ASN1_CONSTRAINTS_ASN1CONSTRAINTSUNION__

#include <hotplace/sdk/io/asn.1/constraints/asn1_constraints.hpp>

namespace hotplace {
namespace io {

/**
 */
class asn1_constraints_union : public asn1_constraints {
   public:
    asn1_constraints_union(asn1_constraints* lhs, asn1_constraints* rhs);
    asn1_constraints_union(const std::initializer_list<asn1_constraints*>& items);
    asn1_constraints_union(const std::initializer_list<int>& items);
    asn1_constraints_union(const std::initializer_list<std::string>& items);
    virtual ~asn1_constraints_union();

    asn1_constraints_union* clone();

    virtual bool is_applicable(asn1_entity_t entity);

    virtual void addref();
    virtual void release();

   protected:
    asn1_constraints_union(const asn1_constraints_union& other);
    asn1_constraints_union& operator=(const asn1_constraints_union& other);

    virtual void represent(stream_t* s, asn1_value* value = nullptr);

   private:
    std::list<asn1_constraints*> _items;
};

}  // namespace io
}  // namespace hotplace

#endif
