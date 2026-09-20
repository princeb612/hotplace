/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1module.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 * 2023.09.01   Soo Han, Kim        refactor
 */

#include <hotplace/test/testcase/io/parser/asn1module.hpp>
#include <hotplace/test/testcase/io/sample.hpp>

return_t prepare_lexer_asn1(lexical_analyzer& lexer) {
    lexer.clear().prepare();
    auto resource = parser_resource::get_instance();
    resource->for_each(resource_type_t::token_type_asn1, [&lexer](uint32 token, const std::string& name) -> void { lexer.add_token(name, token); });
    lexer.get_config().set("handle_comments", 1).set("handle_quoted", 1).set("handle_token", 1);
    lexer.add_token("....", token_ellipsis);  // tokens replaced via block reduction for the PoC
    return errorcode_t::success;
}

return_t prepare_lexer_asn1_usertype(lexical_analyzer& lexer) {
    prepare_lexer_asn1(lexer);
    lexer.get_config().set("handle_lvalue_usertype", 1);
    return errorcode_t::success;
}

return_t prepare_asn1module_reducer(asn1module_reducer_t& ac) {
    ac.group_as(vtoken_symbol, {token_identifier, token_usertype});

    ac.insert_as(vtoken_header_block_start, {vtoken_symbol, token_definitions});
    // id { oid } DEFINITIONS
    // - the id { form is a very common pattern, so we need to organize it in a bit more detail...
    ac.insert_as(vtoken_header_block_start, {vtoken_symbol, token_lbrace, token_identifier, token_lparen, token_number, token_rparen});
    ac.insert_as(vtoken_header_block_end, {token_assign, token_begin});
    ac.insert_as(vtoken_exports_clause_start, {token_exports});
    ac.insert_as(vtoken_imports_clause_start, {token_imports});
    ac.insert_as(vtoken_exports_clause_end, {token_semicolon});

    ac.treat_as(vtoken_header_clause, {vtoken_header_block_start}, {vtoken_header_block_end});
    ac.treat_as(vtoken_exports_clause, {vtoken_exports_clause_start}, {vtoken_exports_clause_end});
    ac.treat_as(vtoken_imports_clause, {vtoken_imports_clause_start}, {vtoken_exports_clause_end});

    ac.build();
    ac.set_greedy_filter(true);

    return errorcode_t::success;
}

return_t ac_search(const asn1module_reducer_t& ac, const char* input, size_t size, std::vector<parser_token>& tokens, std::multimap<range_t, size_t>& search_results) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == input) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        tokens.clear();
        search_results.clear();

        lexical_analyzer lexer;
        lexical_context context;

        // set up tokens
        prepare_lexer_asn1_usertype(lexer);

        // lexer
        lexer.parse(context, input, size);  // ASN1 file

        // make tokens
        uint32 cnt = 0;
        auto lambda = [&](const token_description* desc) -> bool {
            bool ret = true;
            const auto& type = desc->type;
            std::string token(desc->p, desc->size);
            switch (type) {
                case token_lvalue: {
                    tokens.push_back({token_identifier, token});
                } break;
                case token_comments:
                    // do not push into tokens
                    break;
                default: {
                    tokens.push_back({type, token});
                }
            }
            _logger->writeln("[%03u] line %zi type %d(%s) index %d pos %zi len %zi line %zi (%.*s)", cnt++, desc->line, desc->type,
                             lexer.nameof_token(desc->type).c_str(), desc->index, desc->pos, desc->size, desc->line, (unsigned)desc->size, desc->p);
            return ret;
        };
        context.for_each(lambda);

        // search
        search_results = ac.search(tokens.data(), tokens.size());
    }
    __finally2 {}

    return ret;
}

return_t ac_printall(const asn1module_reducer_t& ac, const std::vector<parser_token>& tokens, const std::multimap<range_t, size_t>& search_results) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (true == search_results.empty()) {
            ret = errorcode_t::no_data;
            _logger->writeln("no patterns matched.");
            __leave2;
        }

        print_style_t style;
        style.use_naked();

        auto lambda_dump = [&](const std::multimap<range_t, size_t>& input) -> void {
            _logger->write([&](basic_stream& dbs) -> void {
                auto lambda_print = [&](typename std::multimap<range_t, size_t>::const_iterator iter, basic_stream& dbs) -> void {
                    const range_t& range = iter->first;
                    size_t pattern_id = iter->second;

                    bool is_virtual = ac.is_virtual_pattern(pattern_id);
                    uint32 vtoken = ac.get_virtual_token(pattern_id);

                    dbs << "range [" << range.begin << " .. " << range.end << "] " << "pattern id: " << pattern_id;
                    if (true == is_virtual) {
                        dbs << " (virtual token: " << vtoken << ")";
                    }
                    dbs << "\n  matched tokens: ";
                    for (size_t i = range.begin; i <= range.end; ++i) {
                        dbs << "[" << tokens[i].value << "]";
                    }
                    dbs << "\n";
                };
                print_pair(input, dbs, lambda_print, style);
            });
        };

        _logger->writeln("matched pattern results (greedy filter : %s)", ac.apply_greedy_filter() ? "true" : "false");
        lambda_dump(search_results);
        if (false == ac.apply_greedy_filter()) {
            _logger->writeln("longest pattern results");
            auto results = ac.greedy_filter(search_results);
            lambda_dump(results);
        }
    }
    __finally2 {}
    return ret;
}

return_t ac_search_and_printall(const asn1module_reducer_t& ac, const char* input, size_t size) {
    return_t ret = errorcode_t::success;
    __try2 {
        std::vector<parser_token> tokens;
        std::multimap<range_t, size_t> results;
        ret = ac_search(ac, input, size, tokens, results);
        if (errorcode_t::success != ret) {
            __leave2;
        }
        ret = ac_printall(ac, tokens, results);
        if (errorcode_t::success != ret) {
            __leave2;
        }
    }
    __finally2 { _test_case.test(ret, __FUNCTION__, "aho corasick reduction"); }
    return ret;
}

return_t prepare_asn1notation_grammar(lalr_parser& parser) {
    return_t ret = errorcode_t::success;
#if 0
    auto resource = parser_resource::get_instance();
    auto symid = resource->nameof(token_identifier);     // "identifier"
    auto symnum = resource->nameof(token_number);        // symnum
    auto symfp = resource->nameof(token_floatingpoint);  // "floatingpoint"
    auto symqs = resource->nameof(token_quot_string);    // "quot_string"
    auto symuser = resource->nameof(token_usertype);     // "usertype"

    cfg_grammar grammar;
    grammar
        // Top level & Assignments
        .add_production("S'", {"Statement"})
        .add_production("Statement", {"Assignment"})
        .add_production("Statement", {"TypeSpec"})
        .add_production("Statement", {"Constraint"})
        .add_production("Statement", {"Field"})
        .add_production("Statement", {"TagPrefix"})

        // Assignment: LHS (at the time of asn1_referenced_type::define)
        .add_production("Assignment", {"DefinedType", "::=", "TypeSpec"})
        .add_production("Assignment", {"DefinedType", "::=", "TypeSpec", "Constraint"})

        // LHS type definition symbol
        .add_production("DefinedType", {symuser})
        .add_production("DefinedType", {symid})

        // Structural Statements
        .add_production("StatementSequence", {"SEQUENCE", "Constraint", "{", "FieldList", "}"})
        .add_production("StatementSequence", {"SEQUENCE", "{", "FieldList", "}"})
        .add_production("StatementSequence", {"SEQUENCE", "Constraint", "{", "}"})
        .add_production("StatementSequence", {"SEQUENCE", "{", "}"})
        .add_production("StatementSequenceOf", {"SEQUENCE", "SizeConstraint", "OF", "TypeSpec"})
        .add_production("StatementSequenceOf", {"SEQUENCE", "Constraint", "OF", "TypeSpec"})
        .add_production("StatementSequenceOf", {"SEQUENCE", "OF", "TypeSpec"})
        .add_production("StatementSet", {"SET", "Constraint", "{", "FieldList", "}"})
        .add_production("StatementSet", {"SET", "{", "FieldList", "}"})
        .add_production("StatementSet", {"SET", "Constraint", "{", "}"})
        .add_production("StatementSet", {"SET", "{", "}"})
        .add_production("StatementSetOf", {"SET", "SizeConstraint", "OF", "TypeSpec"})
        .add_production("StatementSetOf", {"SET", "Constraint", "OF", "TypeSpec"})
        .add_production("StatementSetOf", {"SET", "OF", "TypeSpec"})
        .add_production("StatementChoice", {"CHOICE", "Constraint", "{", "FieldList", "}"})
        .add_production("StatementChoice", {"CHOICE", "{", "FieldList", "}"})
        .add_production("StatementChoice", {"CHOICE", "Constraint", "{", "}"})
        .add_production("StatementChoice", {"CHOICE", "{", "}"})

        // Field & Field List
        .add_production("FieldList", {"FieldList", ",", "Field"})
        .add_production("FieldList", {"Field"})
        .add_production("Field", {symid, "TypeSpec"})
        .add_production("Field", {symid, "TypeSpec", "Constraint"})
        .add_production("Field", {symid, "TypeSpec", "FieldOpt"})
        .add_production("Field", {symid, "TypeSpec", "Constraint", "FieldOpt"})
        .add_production("Field", {symuser, "TypeSpec"})
        .add_production("Field", {symuser, "TypeSpec", "Constraint"})
        .add_production("Field", {symuser, "TypeSpec", "FieldOpt"})
        .add_production("Field", {symuser, "TypeSpec", "Constraint", "FieldOpt"})
        .add_production("FieldOpt", {"OPTIONAL"})
        .add_production("FieldOpt", {"DEFAULT", symnum})
        .add_production("FieldOpt", {"DEFAULT", symqs})
        .add_production("FieldOpt", {"DEFAULT", "{", "}"})

        // Type Spec Definition
        .add_production("TypeSpec", {"TypeBase"})
        .add_production("TypeSpec", {"EnumType"})
        .add_production("TypeSpec", {"StatementSequence"})
        .add_production("TypeSpec", {"StatementSequenceOf"})
        .add_production("TypeSpec", {"StatementSet"})
        .add_production("TypeSpec", {"StatementSetOf"})
        .add_production("TypeSpec", {"StatementChoice"})

        // RHS referenced type symbol (asn1_referenced_type::refer time)
        .add_production("TypeBase", {"SimpleType"})
        .add_production("TypeBase", {"TaggedType"})
        .add_production("TypeBase", {"ReferencedType"})

        .add_production("ReferencedType", {symuser})
        .add_production("ReferencedType", {symid})

        // Tagged Type Productions
        .add_production("TaggedType", {"TagPrefix", "TagSpec", "TypeSpec"})
        .add_production("TaggedType", {"TagPrefix", "TypeSpec"})

        // TagPrefix
        .add_production("TagPrefix", {"[", "TagClass", symnum, "]"})
        .add_production("TagPrefix", {"[", symnum, "]"})

        // Tag Class & Spec
        .add_production("TagClass", {"UNIVERSAL"})
        .add_production("TagClass", {"APPLICATION"})
        .add_production("TagClass", {"PRIVATE"})
        .add_production("TagSpec", {"IMPLICIT"})
        .add_production("TagSpec", {"EXPLICIT"})

        // Enum Type
        .add_production("EnumType", {"ENUMERATED", "{", "EnumList", "}"})
        .add_production("EnumList", {"EnumList", ",", "EnumItem"})
        .add_production("EnumList", {"EnumItem"})
        .add_production("EnumItem", {symid, "(", symnum, ")"})

        // Simple Type List
        .add_production("SimpleType", {"BOOLEAN"})
        .add_production("SimpleType", {"INTEGER"})
        .add_production("SimpleType", {"INTEGER", "{", "EnumList", "}"})
        .add_production("SimpleType", {"BIT STRING"})
        .add_production("SimpleType", {"BIT STRING", "{", "EnumList", "}"})
        .add_production("SimpleType", {"OCTET STRING"})
        .add_production("SimpleType", {"NULL"})
        .add_production("SimpleType", {"OBJECT IDENTIFIER"})
        .add_production("SimpleType", {"REAL"})
        .add_production("SimpleType", {"UTF8String"})
        .add_production("SimpleType", {"RELATIVE-OID"})
        .add_production("SimpleType", {"TIME"})
        .add_production("SimpleType", {"NumericString"})
        .add_production("SimpleType", {"PrintableString"})
        .add_production("SimpleType", {"TeletexString"})
        .add_production("SimpleType", {"T61String"})
        .add_production("SimpleType", {"VideotexString"})
        .add_production("SimpleType", {"IA5String"})
        .add_production("SimpleType", {"UTCTime"})
        .add_production("SimpleType", {"GeneralizedTime"})
        .add_production("SimpleType", {"GraphicString"})
        .add_production("SimpleType", {"VisibleString"})
        .add_production("SimpleType", {"ISO646String"})
        .add_production("SimpleType", {"GeneralString"})
        .add_production("SimpleType", {"UniversalString"})
        .add_production("SimpleType", {"CHARACTER STRING"})
        .add_production("SimpleType", {"BMPString"})
        .add_production("SimpleType", {"DATE"})
        .add_production("SimpleType", {"TIME-OF-DAY"})
        .add_production("SimpleType", {"DATE-TIME"})
        .add_production("SimpleType", {"DURATION"})
        .add_production("SimpleType", {"ANY"})

        // 1. Constraints Grammar Top-Level
        .add_production("Constraint", {"(", "ConstraintExpr", ")"})

        // 2. Constraint Expression & Element Sets
        .add_production("ConstraintExpr", {"SubtypeElementSet"})
        .add_production("ConstraintExpr", {"ALL EXCEPT", "SubtypeElementSet"})  // lexer supports single token (token_allexcept)

        // SubtypeElementSet: Handles Union, Except, and consecutive constraints (Intersection) connected by spaces.
        .add_production("SubtypeElementSet", {"SubtypeElementSet", "|", "SubtypeElement"})
        .add_production("SubtypeElementSet", {"SubtypeElementSet", ",", "SubtypeElement"})
        .add_production("SubtypeElementSet", {"SubtypeElementSet", "UNION", "SubtypeElement"})
        .add_production("SubtypeElementSet", {"SubtypeElementSet", "EXCEPT", "SubtypeElement"})
        // support for implicit intersection/range constraints (e.g., from(...) size(...))
        .add_production("SubtypeElementSet", {"SubtypeElementSet", "SubtypeElement"})
        .add_production("SubtypeElementSet", {"SubtypeElement"})

        // SubtypeElement: Explicit Intersection Level
        .add_production("SubtypeElement", {"SubtypeElement", "^", "PrimaryElement"})
        .add_production("SubtypeElement", {"SubtypeElement", "INTERSECTION", "PrimaryElement"})
        .add_production("SubtypeElement", {"PrimaryElement"})

        // 3. Primary Elements (SIZE, FROM, PATTERN, Range, Parenthesized)
        .add_production("PrimaryElement", {"ValueElement"})
        .add_production("PrimaryElement", {"ValueElement", "..", "ValueElement"})            // [from, to]
        .add_production("PrimaryElement", {"ValueElement", "..", "<", "ValueElement"})       // [from, to)
        .add_production("PrimaryElement", {"ValueElement", "<", "..", "ValueElement"})       // (from, to]
        .add_production("PrimaryElement", {"ValueElement", "<", "..", "<", "ValueElement"})  // (from, to)
        .add_production("PrimaryElement", {"SIZE", "Constraint"})
        .add_production("PrimaryElement", {"FROM", "Constraint"})
        .add_production("PrimaryElement", {"PATTERN", symqs})
        .add_production("PrimaryElement", {"(", "ConstraintExpr", ")"})  // parenthesis recursive structure

        .add_production("SizeConstraint", {"SIZE", "Constraint"})

        // 4. Value Elements
        .add_production("ValueElement", {symid})
        .add_production("ValueElement", {symuser})
        .add_production("ValueElement", {symnum})
        .add_production("ValueElement", {symfp})
        .add_production("ValueElement", {symqs})  // quoted string token for processing "ABCDEF"
        .add_production("ValueElement", {"MIN"})
        .add_production("ValueElement", {"MAX"})
        .add_production("ValueElement", {"TRUE"})
        .add_production("ValueElement", {"FALSE"});

    // Terminals
    grammar.add_terminal("::=")
        .add_terminal("{")
        .add_terminal("}")
        .add_terminal(",")
        .add_terminal("[")
        .add_terminal("]")
        .add_terminal("(")
        .add_terminal(")")
        .add_terminal("<")
        .add_terminal("..")
        .add_terminal("|")
        .add_terminal("INTERSECTION")
        .add_terminal("EXCEPT")
        .add_terminal("ALL EXCEPT")
        .add_terminal("ALL")
        .add_terminal("SIZE")
        .add_terminal("FROM")
        .add_terminal("PATTERN")
        .add_terminal("MIN")
        .add_terminal("MAX")
        .add_terminal("OPTIONAL")
        .add_terminal("SEQUENCE")
        .add_terminal("SET")
        .add_terminal("CHOICE")
        .add_terminal("OF")
        .add_terminal("BOOLEAN")
        .add_terminal("INTEGER")
        .add_terminal("REAL")
        .add_terminal("ENUMERATED")
        .add_terminal("OBJECT IDENTIFIER")
        .add_terminal("RELATIVE-OID")
        .add_terminal("UTCTime")
        .add_terminal("GeneralizedTime")
        .add_terminal("UTF8String")
        .add_terminal("VisibleString")
        .add_terminal("IA5String")
        .add_terminal("OCTET STRING")
        .add_terminal("BIT STRING")
        .add_terminal("NULL")
        .add_terminal("ANY")
        .add_terminal("DEFAULT")
        .add_terminal("TRUE")
        .add_terminal("FALSE")
        .add_terminal("UNIVERSAL")
        .add_terminal("APPLICATION")
        .add_terminal("PRIVATE")
        .add_terminal("IMPLICIT")
        .add_terminal("EXPLICIT")
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
    _test_case.test(ret, __FUNCTION__, "build parsing table");
#else
    parser.import(asn1_notation_productions, asn1_notation_action_table, asn1_notation_goto_table);
#endif
    return ret;
}

return_t prepare_asn1module_grammar(lalr_parser& parser) {
    return_t ret = errorcode_t::success;

    // TODO
    // The lexer passes all tokens between BEGIN and END in the form of Epsilon.

#if 0
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
        .add_production("ModuleDefinition", {"ModuleHeader", "ModuleBody", "Statement", "END"})
        .add_production("ModuleDefinition", {"ModuleHeader", "Statement", "END"})

        // OID Component Sequence
        .add_production("OidComponentList", {"OidComponentList", "OidComponent"})
        .add_production("OidComponentList", {"OidComponent"})

        .add_production("OidComponent", {symid, "(", symnum, ")"})

        // Module Header
        .add_production("ModuleHeader", {"ModuleId", "DEFINITIONS", "TagDefault", "ExtImplied", symassign, "BEGIN"})
        .add_production("ModuleHeader", {"ModuleId", "DEFINITIONS", "TagDefault", symassign, "BEGIN"})
        .add_production("ModuleHeader", {"ModuleId", "DEFINITIONS", symassign, "BEGIN"})

        .add_production("ModuleHeader", {"ModuleId", "{", "OidComponentList", "}", "DEFINITIONS", "TagDefault", "ExtImplied", symassign, "BEGIN"})
        .add_production("ModuleHeader", {"ModuleId", "{", "OidComponentList", "}", "DEFINITIONS", "TagDefault", symassign, "BEGIN"})
        .add_production("ModuleHeader", {"ModuleId", "{", "OidComponentList", "}", "DEFINITIONS", symassign, "BEGIN"})

        .add_production("ModuleId", {symuser})
        .add_production("ModuleId", {symid})

        // Header Defaults
        .add_production("TagDefault", {"EXPLICIT", "TAGS"})
        .add_production("TagDefault", {"IMPLICIT", "TAGS"})
        .add_production("TagDefault", {"AUTOMATIC", "TAGS"})

        .add_production("ExtImplied", {"EXTENSIBILITY", "IMPLIED"})

        // Module Body Structure
        .add_production("ModuleBody", {"ExportsClause"})
        .add_production("ModuleBody", {"ImportsClause"})
        .add_production("ModuleBody", {"ExportsClause", "ImportsClause"})
        .add_production("ModuleBody", {"ImportsClause", "ExportsClause"})

        .add_production("Statement", {"...."})

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

        .add_production("SymbolItem", {symuser})
        .add_production("SymbolItem", {symid})
        .add_production("SymbolItem", {symuser, "{", "}"})
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
    _test_case.test(ret, __FUNCTION__, "build parsing table");
#else
    parser.import(asn1_module_productions, asn1_module_action_table, asn1_module_goto_table);
    _test_case.test(ret, __FUNCTION__, "load pre-built table");
#endif
    return ret;
}

void test_asn1parser(lalr_parser& parser, const char* text, const char* input) {
    return_t ret = errorcode_t::success;
    std::vector<parser_token> tokens;

    lexical_analyzer lexer;
    lexical_context context;
    prepare_lexer_asn1_usertype(lexer);

    lexer.parse(context, input);

    uint32 cnt = 0;
    auto lambda = [&](const token_description* desc) -> bool {
        bool ret = true;
        const auto& type = desc->type;
        std::string token(desc->p, desc->size);
        switch (type) {
            case token_lvalue: {
                tokens.push_back({token_identifier, token});
            } break;
            case token_comments:
                break;
            default: {
                tokens.push_back({type, token});
            }
        }
        _logger->writeln("[%03u] line %zi type %d(%s) index %d pos %zi len %zi (%.*s)", cnt++, desc->line, desc->type, lexer.nameof_token(desc->type).c_str(),
                         desc->index, desc->pos, desc->size, (unsigned)desc->size, desc->p);
        return ret;
    };
    context.for_each(lambda);
    tokens.push_back({token_eof, "$"});

    parse_tree pt;
    ret = parser.parse(tokens, &pt);

    dump_parse_tree(pt);

    _logger->writeln("LALR parsing %s.", (errorcode_t::success == ret) ? "completed successfully" : "failed");
    _test_case.test(ret, __FUNCTION__, "parse %s", text);
}

void dump_parse_tree(parse_tree& pt) {
    {
        _logger->colorln("parse tree - re-trace");
        uint32 idx = 0;
        auto lambda = [&idx](parser_action_t type, parse_treenode* node) -> return_t {
            _logger->writeln([&](basic_stream& dbs) -> void {
                valist va;
                va << idx++ << node->symbol << node->value << node->children.size();
                dbs.vaprintf("[{1:03i}] ", va);
                switch (type) {
                    case parser_action_t::shift:
                        dbs << "shift  ";
                        break;
                    case parser_action_t::reduce:
                        dbs << "reduce ";
                        break;
                    default:
                        break;
                }
                dbs.vaprintf("{2}", va);
                if ((false == node->value.empty()) && (node->symbol != node->value)) {
                    dbs.vaprintf(" ({3})", va);
                }
                if (parser_action_t::reduce == type) {
                    dbs.vaprintf(" RHS [{4}]", va);
                }
            });
            return errorcode_t::success;
        };
        parse_tree_visitor visitor(lambda);
        pt.accept(&visitor);
    }
    {
        _logger->colorln("parser tree - graph");
        auto root = pt.get_root();
        if (root) {
            basic_stream bs;
            root->print(bs);
            _logger->write(bs);
        }
    }
}
