/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_constraint_single_value.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * see README.md
 */

#ifndef __HOTPLACE_SDK_IO_ASN1_CONSTRAINTS_ASN1CONSTRAINTSINGLEVALUE__
#define __HOTPLACE_SDK_IO_ASN1_CONSTRAINTS_ASN1CONSTRAINTSINGLEVALUE__

#include <hotplace/sdk/base/basic/variant.hpp>
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
 *                                          new asn1_constraint_single_value(1));
 *                              }));
 */
class asn1_constraint_single_value : public asn1_constraint {
   public:
    asn1_constraint_single_value(const variant& value);
    asn1_constraint_single_value(variant&& value);
    virtual ~asn1_constraint_single_value();

    asn1_constraint_single_value* clone();

    virtual bool is_applicable(asn1_entity_t entity);

   protected:
    asn1_constraint_single_value(const asn1_constraint_single_value& other);
    asn1_constraint_single_value& operator=(const asn1_constraint_single_value& other);

    virtual void represent(stream_t* s, asn1_object* object, asn1_value* value = nullptr);

   private:
    variant _v;
};

}  // namespace io
}  // namespace hotplace

#endif
