/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_constraints_range.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * see README.md
 */

#ifndef __HOTPLACE_SDK_IO_ASN1_CONSTRAINTS_ASN1CONSTRAINTSRANGE__
#define __HOTPLACE_SDK_IO_ASN1_CONSTRAINTS_ASN1CONSTRAINTSRANGE__

#include <hotplace/sdk/base/nostd/range.hpp>
#include <hotplace/sdk/io/asn.1/constraints/asn1_constraints.hpp>

namespace hotplace {
namespace io {

class asn1_constraints_range : public asn1_constraints {
   public:
    asn1_constraints_range(int begin, int end);
    asn1_constraints_range(const t_range_t<int>& r);
    asn1_constraints_range(t_range_t<int>&& r);
    virtual ~asn1_constraints_range();

    asn1_constraints_range* clone();

    virtual bool is_applicable(asn1_entity_t entity);

   protected:
    asn1_constraints_range(const asn1_constraints_range& other);
    asn1_constraints_range& operator=(const asn1_constraints_range& other);

    virtual void represent(stream_t* s, asn1_value* value = nullptr);

   private:
    t_range_t<int> _r;
};

}  // namespace io
}  // namespace hotplace

#endif
