/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_constraint_union.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * see README.md
 */

#ifndef __HOTPLACE_SDK_IO_ASN1_CONSTRAINTS_ASN1CONSTRAINTUNION__
#define __HOTPLACE_SDK_IO_ASN1_CONSTRAINTS_ASN1CONSTRAINTUNION__

#include <hotplace/sdk/io/asn.1/constraints/asn1_constraint.hpp>

namespace hotplace {
namespace io {

/**
 * @example
 *          auto type =
 *              asn1_referenced_type::define("type",
 *                  asn1_builder::build(asn1_entity_integer,
 *                              [&](asn1_builtin_type* builtin) -> void {
 *                                  builtin->get_constraints().add(
 *                                          new asn1_constraint_union(
 *                                              new asn1_constraint_range(1, 10),
 *                                              new asn1_constraint_range(20, 30)));
 *                              }));
 */
class asn1_constraint_union : public asn1_constraint {
   public:
    asn1_constraint_union(asn1_constraint* lhs, asn1_constraint* rhs);
    asn1_constraint_union(const std::initializer_list<asn1_constraint*>& items);
    asn1_constraint_union(const std::initializer_list<int>& items);
    asn1_constraint_union(const std::initializer_list<std::string>& items);
    virtual ~asn1_constraint_union();

    asn1_constraint_union* clone();

    virtual bool is_applicable(asn1_entity_t entity);

    virtual void addref();
    virtual void release();

   protected:
    asn1_constraint_union(const asn1_constraint_union& other);
    asn1_constraint_union& operator=(const asn1_constraint_union& other);

    virtual void represent(stream_t* s, asn1_object* object, asn1_value* value = nullptr);

   private:
    std::list<asn1_constraint*> _items;
};

}  // namespace io
}  // namespace hotplace

#endif
