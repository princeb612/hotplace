/* vim: set tabstop=4 parser_action_t::shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_module_goto.cpp
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
const std::map<std::pair<uint32, std::string>, uint32> asn1_module_goto_table =  //
{
 {{0, "ModuleDefinition"}, 1},
 {{0, "ModuleHeader"}, 2},
 {{0, "ModuleId"}, 3},
 {{2, "ExportsClause"}, 8},
 {{2, "ImportsClause"}, 10},
 {{2, "ModuleBody"}, 11},
 {{2, "Statement"}, 12},
 {{7, "SymbolItem"}, 16},
 {{7, "SymbolList"}, 17},
 {{8, "ImportsClause"}, 20},
 {{9, "SymbolItem"}, 16},
 {{9, "SymbolList"}, 21},
 {{9, "SymbolsFromModule"}, 22},
 {{9, "SymbolsFromModuleList"}, 23},
 {{10, "ExportsClause"}, 24},
 {{11, "Statement"}, 25},
 {{13, "TagDefault"}, 31},
 {{14, "OidComponent"}, 32},
 {{14, "OidComponentList"}, 33},
 {{31, "ExtImplied"}, 49},
 {{33, "OidComponent"}, 50},
 {{36, "SymbolItem"}, 53},
 {{40, "ModuleId"}, 56},
 {{60, "TagDefault"}, 65},
 {{62, "OidComponent"}, 32},
 {{62, "OidComponentList"}, 67},
 {{65, "ExtImplied"}, 70},
 {{67, "OidComponent"}, 50}
};
// clang-format on

}  // namespace io
}  // namespace hotplace
