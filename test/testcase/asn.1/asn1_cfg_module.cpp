/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_cfg_module.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include "asn1_cfg_module.hpp"

return_t prepare_lalr1_parser_asn1_module(parser_t& parser) {
    return_t ret = errorcode_t::success;

    auto resource = parser_resource::get_instance();

    auto symid = resource->nameof(token_identifier);     // "identifier"
    auto symnum = resource->nameof(token_number);        // "number"
    auto symfp = resource->nameof(token_floatingpoint);  // "floatingpoint"
    auto symqs = resource->nameof(token_quot_string);    // "quot_string"
    auto symuser = resource->nameof(token_usertype);     // "usertype"
    auto symassign = resource->nameof(token_assign);     // "::=" (token_assign)

    cfg_grammar grammar;
    grammar
        // Top level Entry Point
        .add_production("S'", {"ModuleDefinition"})
        .add_production("ModuleDefinition", {"ModuleBegin", "SymbolClauses", "Statement", "ModuleEnd"})
        .add_production("ModuleDefinition", {"ModuleBegin", "Statement", "ModuleEnd"})

        // OID Component Sequence
        .add_production("OidComponentList", {"OidComponentList", "OidComponent"})
        .add_production("OidComponentList", {"OidComponent"})

        .add_production("OidComponent", {symid, "(", symnum, ")"})

        // Module Header
        .add_production("ModuleBegin", {"ModuleId", "DEFINITIONS", "TagDefault", "ExtImplied", symassign, "BEGIN"})
        .add_production("ModuleBegin", {"ModuleId", "DEFINITIONS", "TagDefault", symassign, "BEGIN"})
        .add_production("ModuleBegin", {"ModuleId", "DEFINITIONS", symassign, "BEGIN"})
        .add_production("ModuleBegin", {"ModuleId", "{", "OidComponentList", "}", "DEFINITIONS", "TagDefault", "ExtImplied", symassign, "BEGIN"})
        .add_production("ModuleBegin", {"ModuleId", "{", "OidComponentList", "}", "DEFINITIONS", "TagDefault", symassign, "BEGIN"})
        .add_production("ModuleBegin", {"ModuleId", "{", "OidComponentList", "}", "DEFINITIONS", symassign, "BEGIN"})
        .add_production("ModuleEnd", {"END"})

        .add_production("ModuleId", {symid})

        // Header Defaults
        .add_production("TagDefault", {"EXPLICIT", "TAGS"})
        .add_production("TagDefault", {"IMPLICIT", "TAGS"})
        .add_production("TagDefault", {"AUTOMATIC", "TAGS"})

        .add_production("ExtImplied", {"EXTENSIBILITY", "IMPLIED"})

        // Module Body Structure
        .add_production("SymbolClauses", {"ExportsClause"})
        .add_production("SymbolClauses", {"ImportsClause"})
        .add_production("SymbolClauses", {"ExportsClause", "ImportsClause"})
        .add_production("SymbolClauses", {"ImportsClause", "ExportsClause"})

        .add_production("Statement", {"...."})  // for a test PoC

        // Exports Clause
        .add_production("ExportsClause", {"EXPORTS", "SymbolList", ";"})
        .add_production("ExportsClause", {"EXPORTS", "ALL", ";"})

        // Imports Clause
        .add_production("ImportsClause", {"IMPORTS", "SymbolsFromModuleList", ";"})

        // Imports Modules Specification
        .add_production("SymbolsFromModuleList", {"SymbolsFromModule"})
        .add_production("SymbolsFromModule", {"SymbolList", "FROM", "ModuleId"})
        .add_production("SymbolsFromModule", {"SymbolList", "FROM", "ModuleId", "{", "OidComponentList", "}"})

        // Symbol Lists
        .add_production("SymbolList", {"SymbolList", ",", "SymbolItem"})
        .add_production("SymbolList", {"SymbolItem"})

        // .add_production("SymbolItem", {symuser})
        .add_production("SymbolItem", {symid})
        // .add_production("SymbolItem", {symuser, "{", "}"})
        .add_production("SymbolItem", {symid, "{", "}"});

    // Terminals Registration
    grammar
        //
        .add_terminal("DEFINITIONS")
        .add_terminal("AUTOMATIC")
        .add_terminal("EXPLICIT")
        .add_terminal("IMPLICIT")
        .add_terminal("TAGS")
        .add_terminal("EXTENSIBILITY")
        .add_terminal("IMPLIED")
        .add_terminal("EXPORTS")
        .add_terminal("IMPORTS")
        .add_terminal("FROM")
        .add_terminal("ALL")
        .add_terminal("BEGIN")
        .add_terminal("END")
        .add_terminal("Statement")
        .add_terminal("....")
        .add_terminal("{")
        .add_terminal("}")
        .add_terminal("(")
        .add_terminal(")")
        .add_terminal(",")
        .add_terminal(";")
        .add_terminal(symassign)
        .add_terminal(symid)
        .add_terminal(symuser)
        .add_terminal(symnum)
        .add_terminal(symfp)
        .add_terminal(symqs)
        .add_terminal("$");

    parser.set_grammar(std::move(grammar));

    _logger->writeln("building LALR(1) parsing table dynamically...");

    ret = parser.learn();
    _logger->writeln("LALR table generation %s", (errorcode_t::success == ret) ? "success" : "failure");
    _test_case.test(ret, __FUNCTION__, "LALR(1) parser - ASSN.1 for Module (build parsing table)");

    return ret;
}

parser_t& get_glr_parser_asn1_module_by_build() {
    static glr_parser parser;
    static const return_t ready = prepare_lalr1_parser_asn1_module(parser);
    (void)ready;
    return parser;
}
