/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   types.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_IO_ASN1_BASIC_TYPES__
#define __HOTPLACE_SDK_IO_ASN1_BASIC_TYPES__

#include <hotplace/sdk/io/asn.1/types.hpp>

namespace hotplace {
namespace io {

enum asn1_visitor_flag_t : uint16 {
    asn1_visitor_sequence_of = 1,
    asn1_visitor_set_of = 2,
    asn1_visitor_choice = 3,
};

// print_ast
enum asn1_ast_flags : uint32 {
    asn1_ast_flag_ansicolor = 1 << 0,
};

using asn1_native_int_t = int64;

class asn1_object;
class asn1_type;
class asn1_builtin_type;
class asn1_referenced_type;
class asn1_tag;
class asn1_tagged_type;
class asn1_container;
class asn1_sequence;
class asn1_sequence_of;
class asn1_set;
class asn1_set_of;
class asn1_choice;
class asn1_enum;
class asn1_bitstring;  // named bit list
class asn1_integer;    // named number list
class asn1_namedlist;
class asn1_unknown_container;

class asn1_encode;
class asn1_resource;

class asn1_value;

class asn1_visitor;
class asn1_der_visitor;
class asn1_notation_visitor;
class asn1_ast_visitor;

class asn1_constraint_visitor;
class asn1_constraint_notation_visitor;
template <typename T>
class asn1_constraint_evaluator;

class asn1_constraint_t;
class asn1_constraints;

class asn1_node;
class asn1_constructed_node;
class asn1_primitive_node;

}  // namespace io
}  // namespace hotplace

#endif
