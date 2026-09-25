/* vim: set tabstop=4 parser_action_t::shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_allin1_terminals.cpp
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
const std::set<std::string> asn1_allin1_terminals = //
{
 {SYMBOL_NUM},
 {SYMBOL_ID},
 {SYMBOL_FP},
 {"("},
 {")"},
 {"["},
 {"]"},
 {"{"},
 {"}"},
 {"::="},
 {"<"},
 {":"},
 {";"},
 {","},
 {"."},
 {"&"},
 {SYMBOL_QSTR},
 {"@"},
 {SYMBOL_USERTYPE},
 {"BOOLEAN"},
 {"INTEGER"},
 {"BIT STRING"},
 {"OCTET STRING"},
 {"NULL"},
 {"OBJECT IDENTIFIER"},
 {"REAL"},
 {"ENUMERATED"},
 {"UTF8String"},
 {"RELATIVE-OID"},
 {"PrintableString"},
 {"TeletexString"},
 {"T61String"},
 {"VideotexString"},
 {"IA5String"},
 {"UTCTime"},
 {"GeneralizedTime"},
 {"GraphicString"},
 {"VisibleString"},
 {"ISO646String"},
 {"GeneralString"},
 {"UniversalString"},
 {"CHARACTER STRING"},
 {"BMPString"},
 {"DATE"},
 {"TIME-OF-DAY"},
 {"DATE-TIME"},
 {"DURATION"},
 {"ANY"},
 {"SEQUENCE"},
 {"SET"},
 {"CHOICE"},
 {"OF"},
 {"TRUE"},
 {"FALSE"},
 {"UNIVERSAL"},
 {"APPLICATION"},
 {"PRIVATE"},
 {"IMPLICIT"},
 {"EXPLICIT"},
 {"DEFAULT"},
 {"OPTIONAL"},
 {"UNION"},
 {"|"},
 {"INTERSECTION"},
 {"^"},
 {"EXCEPT"},
 {"ALL EXCEPT"},
 {"SIZE"},
 {"FROM"},
 {"PATTERN"},
 {"MIN"},
 {"MAX"},
 {".."},
 {"DEFINITIONS"},
 {"AUTOMATIC"},
 {"TAGS"},
 {"BEGIN"},
 {"END"},
 {"EXPORTS"},
 {"IMPORTS"},
 {"ALL"},
 {"EXTENSIBILITY"},
 {"IMPLIED"},
 {SYMBOL_USERPARAMTYPE},
 {SYMBOL_PARAMTYPE},
 {SYMBOL_PARAMVALUE},
 {"CLASS"},
 {"WITH"},
 {"SYNTAX"},
 {"UNIQUE"},
 {"$"},
};
// clang-format on

}  // namespace io
}  // namespace hotplace
