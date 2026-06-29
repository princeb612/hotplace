/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_constraint_range.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * see README.md
 */

#ifndef __HOTPLACE_SDK_IO_ASN1_CONSTRAINTS_ASN1CONSTRAINTRANGE__
#define __HOTPLACE_SDK_IO_ASN1_CONSTRAINTS_ASN1CONSTRAINTRANGE__

#include <hotplace/sdk/base/nostd/range_set.hpp>
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
 *                                          new asn1_constraint_intersection(
 *                                              new asn1_constraint_range(1, 100),
 *                                              new asn1_constraint_range(50, 200)));
 *                              }));
 */
class asn1_constraint_range : public asn1_constraint {
    friend class asn1_constraint_size;

   public:
    asn1_constraint_range(t_range_value<int> low, t_range_value<int> high);
    virtual ~asn1_constraint_range();

    asn1_constraint_range* clone();

    virtual bool is_applicable(asn1_entity_t entity);

   protected:
    asn1_constraint_range(const asn1_constraint_range& other);
    asn1_constraint_range& operator=(const asn1_constraint_range& other);

    virtual void represent(stream_t* s, asn1_object* object, asn1_value* value = nullptr);

   private:
    t_range_value<int> _low;
    t_range_value<int> _high;
};

}  // namespace io
}  // namespace hotplace

#endif
