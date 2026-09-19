/* vim: set tabstop=4 parser_action_t::shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_lalr_terminals.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * see README.md
 */

#include <hotplace/sdk/io/asn.1/asn1_resource.hpp>

namespace hotplace {
namespace io {

// clang-format off
const std::set<std::string> asn1_terminals = //
{
 {"DEFINITIONS"},
 {"BEGIN"},
 {"END"},
 {"TAGS"},
 {"AUTOMATIC"},
 {"EXPORTS"},
 {"IMPORTS"},
 {";"},
 {"::="},
 {"{"},
 {"}"},
 {","},
 {"["},
 {"]"},
 {"("},
 {")"},
 {"<"},
 {".."},
 {"|"},
 {"INTERSECTION"},
 {"EXCEPT"},
 {"ALL EXCEPT"},
 {"ALL"},
 {"SIZE"},
 {"FROM"},
 {"PATTERN"},
 {"MIN"},
 {"MAX"},
 {"OPTIONAL"},
 {"SEQUENCE"},
 {"SET"},
 {"CHOICE"},
 {"OF"},
 {"BOOLEAN"},
 {"INTEGER"},
 {"REAL"},
 {"ENUMERATED"},
 {"OBJECT IDENTIFIER"},
 {"RELATIVE-OID"},
 {"UTCTime"},
 {"GeneralizedTime"},
 {"UTF8String"},
 {"VisibleString"},
 {"IA5String"},
 {"OCTET STRING"},
 {"BIT STRING"},
 {"NULL"},
 {"ANY"},
 {"DEFAULT"},
 {"TRUE"},
 {"FALSE"},
 {"UNIVERSAL"},
 {"APPLICATION"},
 {"PRIVATE"},
 {"IMPLICIT"},
 {"EXPLICIT"},
 {SYMBOL_ID},
 {SYMBOL_USERTYPE},
 {SYMBOL_NUM},
 {SYMBOL_FP},
 {SYMBOL_QSTR},
 {"$"},
};
// clang-format on

}  // namespace io
}  // namespace hotplace
