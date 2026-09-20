/* vim: set tabstop=4 parser_action_t::shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_module_terminals.cpp
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
const std::set<std::string> asn1_module_terminals = //
{
 {"DEFINITIONS"},
 {"AUTOMATIC"},
 {"EXPLICIT"},
 {"IMPLICIT"},
 {"TAGS"},
 {"EXTENSIBILITY"},
 {"IMPLIED"},
 {"EXPORTS"},
 {"IMPORTS"},
 {"FROM"},
 {"ALL"},
 {"BEGIN"},
 {"END"},
 {"Statement"},
 {"...."},
 {"{"},
 {"}"},
 {"("},
 {")"},
 {","},
 {";"},
 {"::="},
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
