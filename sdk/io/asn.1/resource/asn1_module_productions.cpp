/* vim: set tabstop=4 parser_action_t::shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_module_productions.cpp
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
const std::vector<parser_production> asn1_module_productions = //
{
 {0, "S\'", {"ModuleDefinition"}},
 {1, "ModuleDefinition", {"ModuleHeader", "ModuleBody", "Statement", "END"}},
 {2, "ModuleDefinition", {"ModuleHeader", "Statement", "END"}},
 {3, "OidComponentList", {"OidComponentList", "OidComponent"}},
 {4, "OidComponentList", {"OidComponent"}},
 {5, "OidComponent", {SYMBOL_ID, "(", SYMBOL_NUM, ")"}},
 {6, "ModuleHeader", {"ModuleId", "DEFINITIONS", "TagDefault", "ExtImplied", "::=", "BEGIN"}},
 {7, "ModuleHeader", {"ModuleId", "DEFINITIONS", "TagDefault", "::=", "BEGIN"}},
 {8, "ModuleHeader", {"ModuleId", "DEFINITIONS", "::=", "BEGIN"}},
 {9, "ModuleHeader", {"ModuleId", "{", "OidComponentList", "}", "DEFINITIONS", "TagDefault", "ExtImplied", "::=", "BEGIN"}},
 {10, "ModuleHeader", {"ModuleId", "{", "OidComponentList", "}", "DEFINITIONS", "TagDefault", "::=", "BEGIN"}},
 {11, "ModuleHeader", {"ModuleId", "{", "OidComponentList", "}", "DEFINITIONS", "::=", "BEGIN"}},
 {12, "ModuleId", {SYMBOL_USERTYPE}},
 {13, "ModuleId", {SYMBOL_ID}},
 {14, "TagDefault", {"EXPLICIT", "TAGS"}},
 {15, "TagDefault", {"IMPLICIT", "TAGS"}},
 {16, "TagDefault", {"AUTOMATIC", "TAGS"}},
 {17, "ExtImplied", {"EXTENSIBILITY", "IMPLIED"}},
 {18, "ModuleBody", {"ExportsClause"}},
 {19, "ModuleBody", {"ImportsClause"}},
 {20, "ModuleBody", {"ExportsClause", "ImportsClause"}},
 {21, "ModuleBody", {"ImportsClause", "ExportsClause"}},
 {22, "Statement", {"...."}},
 {23, "ExportsClause", {"EXPORTS", "SymbolList", ";"}},
 {24, "ExportsClause", {"EXPORTS", "ALL", ";"}},
 {25, "ImportsClause", {"IMPORTS", "SymbolsFromModuleList", ";"}},
 {26, "SymbolsFromModuleList", {"SymbolsFromModule"}},
 {27, "SymbolsFromModule", {"SymbolList", "FROM", "ModuleId"}},
 {28, "SymbolsFromModule", {"SymbolList", "FROM", "ModuleId", "{", "OidComponentList", "}"}},
 {29, "SymbolList", {"SymbolList", ",", "SymbolItem"}},
 {30, "SymbolList", {"SymbolItem"}},
 {31, "SymbolItem", {SYMBOL_USERTYPE}},
 {32, "SymbolItem", {SYMBOL_ID}},
 {33, "SymbolItem", {SYMBOL_USERTYPE, "{", "}"}},
 {34, "SymbolItem", {SYMBOL_ID, "{", "}"}},
};
// clang-format on

}  // namespace io
}  // namespace hotplace
