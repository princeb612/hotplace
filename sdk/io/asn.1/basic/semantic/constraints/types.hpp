/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   types.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * see README.md
 */

#ifndef __HOTPLACE_SDK_IO_ASN1_BASIC_SEMANTIC_CONSTRAINTS_TYPES__
#define __HOTPLACE_SDK_IO_ASN1_BASIC_SEMANTIC_CONSTRAINTS_TYPES__

#include <hotplace/sdk/io/asn.1/basic/semantic/types.hpp>

namespace hotplace {
namespace io {

// clang-format off
template <typename T> class asn1_constraint;
template <typename T> class asn1_constraint_union;
template <typename T> class asn1_constraint_intersection;
template <typename T> class asn1_constraint_except;
template <typename T> class asn1_constraint_all_except;
template <typename T> class asn1_constraint_from;
template <typename T> class asn1_constraint_pattern;
template <typename T> class asn1_constraint_range;
template <typename T> class asn1_constraint_single_value;
template <typename T> class asn1_constraint_size;
// template <typename T, typename std::enable_if<std::is_same<T, std::string>::value, int>::type = 0> asn1_constraint_from;
// template <typename T, typename std::enable_if<std::is_same<T, std::string>::value, int>::type = 0> asn1_constraint_pattern;
// template <typename T, typename std::enable_if<custom::is_integral<typename std::decay<T>::type>::value, int>::type = 0> class asn1_constraint_size;
// clang-format on

using asn1_native_int_t = int64;
using asn1_constraint_all_except_f = asn1_constraint_all_except<double>;
using asn1_constraint_except_f = asn1_constraint_except<double>;
using asn1_constraint_intersection_f = asn1_constraint_intersection<double>;
using asn1_constraint_range_f = asn1_constraint_range<double>;
using asn1_constraint_single_value_f = asn1_constraint_single_value<double>;
using asn1_constraint_union_f = asn1_constraint_union<double>;
using asn1_constraint_all_except_i = asn1_constraint_all_except<asn1_native_int_t>;
using asn1_constraint_except_i = asn1_constraint_except<asn1_native_int_t>;
using asn1_constraint_intersection_i = asn1_constraint_intersection<asn1_native_int_t>;
using asn1_constraint_range_i = asn1_constraint_range<asn1_native_int_t>;
using asn1_constraint_single_value_i = asn1_constraint_single_value<asn1_native_int_t>;
using asn1_constraint_size_i = asn1_constraint_size<asn1_native_int_t>;
using asn1_constraint_union_i = asn1_constraint_union<asn1_native_int_t>;
using asn1_constraint_all_except_s = asn1_constraint_all_except<std::string>;
using asn1_constraint_except_s = asn1_constraint_except<std::string>;
using asn1_constraint_intersection_s = asn1_constraint_intersection<std::string>;
using asn1_constraint_from_s = asn1_constraint_from<std::string>;
using asn1_constraint_range_s = asn1_constraint_range<std::string>;
using asn1_constraint_single_value_s = asn1_constraint_single_value<std::string>;
using asn1_constraint_union_s = asn1_constraint_union<std::string>;
using asn1_constraint_pattern_s = asn1_constraint_pattern<std::string>;

class asn1_constraint_t {
   public:
    virtual ~asn1_constraint_t() = default;

    virtual asn1_constraint_t* clone() = 0;

    virtual asn1_entity_t get_entity() const = 0;
    virtual bool is_operation() const = 0;

    virtual void accept(asn1_constraint_visitor* v) = 0;
    virtual void represent(stream_t* s, const asn1_object* object, const asn1_value* value = nullptr) const = 0;

    virtual type_category_t type() const = 0;

    virtual void addref() = 0;
    virtual void release() = 0;
};

}  // namespace io
}  // namespace hotplace

#endif
