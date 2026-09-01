/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_constraint_pattern.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * see README.md
 */

#ifndef __HOTPLACE_SDK_IO_ASN1_BASIC_SEMANTIC_CONSTRAINTS_ASN1CONSTRAINTPATTERN__
#define __HOTPLACE_SDK_IO_ASN1_BASIC_SEMANTIC_CONSTRAINTS_ASN1CONSTRAINTPATTERN__

#include <hotplace/sdk/io/asn.1/basic/semantic/constraints/asn1_constraint.hpp>

namespace hotplace {
namespace io {

template <typename T>
class asn1_constraint_pattern : public asn1_constraint<T> {
   public:
    asn1_constraint_pattern(const std::string& pattern) : asn1_constraint<T>(asn1_entity_constraint_pattern), _pattern(pattern) {}
    virtual ~asn1_constraint_pattern() = default;

    asn1_constraint_pattern* clone() { return new asn1_constraint_pattern(*this); }

    virtual void accept(asn1_constraint_evaluator<T>* v) { v->get_result_set().insert(_pattern); }

    virtual void represent(stream_t* s, const asn1_object* object, const asn1_value* value = nullptr) const { s->printf(R"(PATTERN "%s")", _pattern.c_str()); }

   private:
    std::string _pattern;
};

}  // namespace io
}  // namespace hotplace

#endif
