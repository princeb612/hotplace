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
    lexer.get_config().set("handle_lvalue_usertype", 1).set("handle_asn1parameterized", 1);
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
    ac.insert_as(vtoken_endof_module, {token_end});

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

return_t prepare_asn1notation_grammar(parser_t& parser) {
    return_t ret = errorcode_t::success;
#if 1
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

        .add_production("Assignment", {"DefinedType", "::=", "TypeSpec"})
        .add_production("Assignment", {"DefinedType", "::=", "TypeSpec", "Constraint"})

        .add_production("DefinedType", {symuser})

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

        .add_production("FieldList", {"FieldList", ",", "Field"})
        .add_production("FieldList", {"Field"})
        .add_production("Field", {symid, "TypeSpec"})
        .add_production("Field", {symid, "TypeSpec", "Constraint"})
        .add_production("Field", {symid, "TypeSpec", "FieldOpt"})
        .add_production("Field", {symid, "TypeSpec", "Constraint", "FieldOpt"})
        .add_production("FieldOpt", {"OPTIONAL"})
        .add_production("FieldOpt", {"DEFAULT", symnum})
        .add_production("FieldOpt", {"DEFAULT", symqs})
        .add_production("FieldOpt", {"DEFAULT", "{", "}"})

        .add_production("TypeSpec", {"TypeBase"})
        .add_production("TypeSpec", {"EnumType"})
        .add_production("TypeSpec", {"StatementSequence"})
        .add_production("TypeSpec", {"StatementSequenceOf"})
        .add_production("TypeSpec", {"StatementSet"})
        .add_production("TypeSpec", {"StatementSetOf"})
        .add_production("TypeSpec", {"StatementChoice"})

        .add_production("TypeBase", {"SimpleType"})
        .add_production("TypeBase", {"TaggedType"})
        .add_production("TypeBase", {"ReferencedType"})

        .add_production("ReferencedType", {symid})

        .add_production("TaggedType", {"TagPrefix", "TagSpec", "TypeSpec"})
        .add_production("TaggedType", {"TagPrefix", "TypeSpec"})

        .add_production("TagPrefix", {"[", "TagClass", symnum, "]"})
        .add_production("TagPrefix", {"[", symnum, "]"})

        .add_production("TagClass", {"UNIVERSAL"})
        .add_production("TagClass", {"APPLICATION"})
        .add_production("TagClass", {"PRIVATE"})
        .add_production("TagSpec", {"IMPLICIT"})
        .add_production("TagSpec", {"EXPLICIT"})

        .add_production("EnumType", {"ENUMERATED", "{", "EnumList", "}"})
        .add_production("EnumList", {"EnumList", ",", "EnumItem"})
        .add_production("EnumList", {"EnumItem"})
        .add_production("EnumItem", {symid, "(", symnum, ")"})

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

        .add_production("Constraint", {"(", "ConstraintExpr", ")"})

        .add_production("ConstraintExpr", {"SubtypeElementSet"})
        .add_production("ConstraintExpr", {"ALL EXCEPT", "SubtypeElementSet"})  // lexer supports single token (token_allexcept)

        .add_production("SubtypeElementSet", {"SubtypeElementSet", "|", "SubtypeElement"})
        .add_production("SubtypeElementSet", {"SubtypeElementSet", ",", "SubtypeElement"})
        .add_production("SubtypeElementSet", {"SubtypeElementSet", "UNION", "SubtypeElement"})
        .add_production("SubtypeElementSet", {"SubtypeElementSet", "EXCEPT", "SubtypeElement"})
        .add_production("SubtypeElementSet", {"SubtypeElementSet", "SubtypeElement"})
        .add_production("SubtypeElementSet", {"SubtypeElement"})

        .add_production("SubtypeElement", {"SubtypeElement", "^", "PrimaryElement"})
        .add_production("SubtypeElement", {"SubtypeElement", "INTERSECTION", "PrimaryElement"})
        .add_production("SubtypeElement", {"PrimaryElement"})

        .add_production("PrimaryElement", {"ValueElement"})
        .add_production("PrimaryElement", {"ValueElement", "..", "ValueElement"})            // [from, to]
        .add_production("PrimaryElement", {"ValueElement", "..", "<", "ValueElement"})       // [from, to)
        .add_production("PrimaryElement", {"ValueElement", "<", "..", "ValueElement"})       // (from, to]
        .add_production("PrimaryElement", {"ValueElement", "<", "..", "<", "ValueElement"})  // (from, to)
        .add_production("PrimaryElement", {"SIZE", "Constraint"})
        .add_production("PrimaryElement", {"FROM", "Constraint"})
        .add_production("PrimaryElement", {"PATTERN", symqs})
        .add_production("PrimaryElement", {"(", "ConstraintExpr", ")"})

        .add_production("SizeConstraint", {"SIZE", "Constraint"})

        .add_production("ValueElement", {symnum})
        .add_production("ValueElement", {symfp})
        .add_production("ValueElement", {symqs})
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

return_t prepare_asn1module_grammar(parser_t& parser) {
    return_t ret = errorcode_t::success;

    // TODO
    // The lexer passes all tokens between BEGIN and END in the form of Epsilon.

#if 1
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

return_t prepare_asn1parameterized_grammar(parser_t& parser) {
    return_t ret = errorcode_t::success;
#if 1
    auto resource = parser_resource::get_instance();
    // Fetch terminal symbol string representations
    auto symid = resource->nameof(token_identifier);                // "identifier"
    auto symnum = resource->nameof(token_number);                   // "number"
    auto symfp = resource->nameof(token_floatingpoint);             // "floatingpoint"
    auto symqs = resource->nameof(token_quot_string);               // "quot_string"
    auto symuser = resource->nameof(token_usertype);                // "usertype"
    auto symuserparamtype = resource->nameof(token_userparamtype);  // "userparamtype"
    auto symparamtype = resource->nameof(token_paramtype);          // "paramtype"
    auto symparamvalue = resource->nameof(token_paramvalue);        // "paramvalue"

    cfg_grammar grammar;
    grammar
        // Top level Entry Point
        .add_production("S'", {"Statement"})

        .add_production("Statement", {"Assignment"})
        .add_production("Statement", {"TypeSpec"})
        .add_production("Statement", {"Constraint"})
        .add_production("Statement", {"Field"})
        .add_production("Statement", {"TagPrefix"})

        .add_production("Assignment", {symuserparamtype, "{", "DummyParamList", "}", "::=", "TypeSpec"})
        .add_production("Assignment", {symuserparamtype, "{", "DummyParamList", "}", "::=", "TypeSpec", "Constraint"})
        .add_production("Assignment", {"DefinedType", "::=", "TypeSpec"})
        .add_production("Assignment", {"DefinedType", "::=", "TypeSpec", "Constraint"})

        .add_production("DefinedType", {symuser})

        .add_production("DummyParamList", {"DummyParamList", ",", "DummyParam"})
        .add_production("DummyParamList", {"DummyParam"})

        .add_production("DummyParam", {symparamtype})
        .add_production("DummyParam", {"TypeSpec", ":", symparamvalue})
        .add_production("DummyParam", {symparamtype, ":", symparamvalue})

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

        .add_production("FieldList", {"FieldList", ",", "Field"})
        .add_production("FieldList", {"Field"})

        .add_production("Field", {symid, "TypeSpec"})
        .add_production("Field", {symid, "TypeSpec", "Constraint"})
        .add_production("Field", {symid, "TypeSpec", "FieldOpt"})
        .add_production("Field", {symid, "TypeSpec", "Constraint", "FieldOpt"})

        .add_production("FieldOpt", {"OPTIONAL"})
        .add_production("FieldOpt", {"DEFAULT", "ValueElement"})
        .add_production("FieldOpt", {"DEFAULT", "{", "}"})

        .add_production("TypeSpec", {"TypeBase"})
        .add_production("TypeSpec", {"EnumType"})
        .add_production("TypeSpec", {"StatementSequence"})
        .add_production("TypeSpec", {"StatementSequenceOf"})
        .add_production("TypeSpec", {"StatementSet"})
        .add_production("TypeSpec", {"StatementSetOf"})
        .add_production("TypeSpec", {"StatementChoice"})

        .add_production("TypeBase", {"SimpleType"})
        .add_production("TypeBase", {"TaggedType"})
        .add_production("TypeBase", {"ReferencedType"})

        .add_production("ReferencedType", {symid})
        .add_production("ReferencedType", {symparamtype})
        .add_production("ReferencedType", {symuserparamtype, "{", "ActualParamList", "}"})
        .add_production("ReferencedType", {symid, "{", "ActualParamList", "}"})

        .add_production("ActualParamList", {"ActualParamList", ",", "ActualParam"})
        .add_production("ActualParamList", {"ActualParam"})

        .add_production("ActualParam", {"TypeSpec"})
        .add_production("ActualParam", {symnum})
        .add_production("ActualParam", {symfp})
        .add_production("ActualParam", {symqs})
        .add_production("ActualParam", {"TRUE"})
        .add_production("ActualParam", {"FALSE"})

        .add_production("TaggedType", {"TagPrefix", "TagSpec", "TypeSpec"})
        .add_production("TaggedType", {"TagPrefix", "TypeSpec"})

        .add_production("TagPrefix", {"[", "TagClass", symnum, "]"})
        .add_production("TagPrefix", {"[", symnum, "]"})

        .add_production("TagClass", {"UNIVERSAL"})
        .add_production("TagClass", {"APPLICATION"})
        .add_production("TagClass", {"PRIVATE"})

        .add_production("TagSpec", {"IMPLICIT"})
        .add_production("TagSpec", {"EXPLICIT"})

        .add_production("EnumType", {"ENUMERATED", "{", "EnumList", "}"})
        .add_production("EnumList", {"EnumList", ",", "EnumItem"})
        .add_production("EnumList", {"EnumItem"})
        .add_production("EnumItem", {symid, "(", symnum, ")"})

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

        .add_production("Constraint", {"(", "ConstraintExpr", ")"})

        .add_production("ConstraintExpr", {"SubtypeElementSet"})
        .add_production("ConstraintExpr", {"ALL EXCEPT", "SubtypeElementSet"})

        .add_production("SubtypeElementSet", {"SubtypeElementSet", "|", "SubtypeElement"})
        .add_production("SubtypeElementSet", {"SubtypeElementSet", ",", "SubtypeElement"})
        .add_production("SubtypeElementSet", {"SubtypeElementSet", "UNION", "SubtypeElement"})
        .add_production("SubtypeElementSet", {"SubtypeElementSet", "EXCEPT", "SubtypeElement"})
        .add_production("SubtypeElementSet", {"SubtypeElementSet", "SubtypeElement"})
        .add_production("SubtypeElementSet", {"SubtypeElement"})

        .add_production("SubtypeElement", {"SubtypeElement", "^", "PrimaryElement"})
        .add_production("SubtypeElement", {"SubtypeElement", "INTERSECTION", "PrimaryElement"})
        .add_production("SubtypeElement", {"PrimaryElement"})

        .add_production("PrimaryElement", {"ValueElement"})
        .add_production("PrimaryElement", {"ValueElement", "..", "ValueElement"})
        .add_production("PrimaryElement", {"ValueElement", "..", "<", "ValueElement"})
        .add_production("PrimaryElement", {"ValueElement", "<", "..", "ValueElement"})
        .add_production("PrimaryElement", {"ValueElement", "<", "..", "<", "ValueElement"})
        .add_production("PrimaryElement", {"SIZE", "Constraint"})
        .add_production("PrimaryElement", {"FROM", "Constraint"})
        .add_production("PrimaryElement", {"PATTERN", symqs})
        .add_production("PrimaryElement", {"(", "ConstraintExpr", ")"})

        .add_production("SizeConstraint", {"SIZE", "Constraint"})

        .add_production("ValueElement", {symparamvalue})
        .add_production("ValueElement", {symnum})
        .add_production("ValueElement", {symfp})
        .add_production("ValueElement", {symqs})
        .add_production("ValueElement", {"MIN"})
        .add_production("ValueElement", {"MAX"})
        .add_production("ValueElement", {"TRUE"})
        .add_production("ValueElement", {"FALSE"});

    // Terminals Registration
    grammar.add_terminal("::=")
        .add_terminal(":")
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
        .add_terminal("^")
        .add_terminal("INTERSECTION")
        .add_terminal("UNION")
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
        .add_terminal("PrintableString")
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
        .add_terminal(symuserparamtype)
        .add_terminal(symparamtype)
        .add_terminal(symparamvalue)
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

return_t prepare_asn1_grammar(parser_t& parser) {
    return_t ret = errorcode_t::success;
    __try2 {
        auto resource = parser_resource::get_instance();
        if (nullptr == resource) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto symid = resource->nameof(token_identifier);                // "identifier"
        auto symnum = resource->nameof(token_number);                   // "number"
        auto symfp = resource->nameof(token_floatingpoint);             // "floatingpoint"
        auto symqs = resource->nameof(token_quot_string);               // "quot_string"
        auto symuser = resource->nameof(token_usertype);                // "usertype"
        auto symuserparamtype = resource->nameof(token_userparamtype);  // "userparamtype"
        auto symparamtype = resource->nameof(token_paramtype);          // "paramtype"
        auto symparamvalue = resource->nameof(token_paramvalue);        // "paramvalue"
        auto symassign = resource->nameof(token_assign);                // "::="

        cfg_grammar grammar;

        grammar
            // Single Top-Level Entry Point
            .add_production("S'", {"Start"})

            .add_production("Start", {"ModuleDefinition"})
            .add_production("Start", {"StatementList"})

            // Module Definition
            .add_production("ModuleDefinition", {"ModuleHeader", "ModuleBody", "StatementList", "END"})
            .add_production("ModuleDefinition", {"ModuleHeader", "StatementList", "END"})
            .add_production("ModuleDefinition", {"ModuleHeader", "END"})

            .add_production("ModuleHeader", {"ModuleId", "DEFINITIONS", "TagDefault", "ExtImplied", symassign, "BEGIN"})
            .add_production("ModuleHeader", {"ModuleId", "DEFINITIONS", "TagDefault", symassign, "BEGIN"})
            .add_production("ModuleHeader", {"ModuleId", "DEFINITIONS", symassign, "BEGIN"})
            .add_production("ModuleHeader", {"ModuleId", "{", "OidComponentList", "}", "DEFINITIONS", "TagDefault", "ExtImplied", symassign, "BEGIN"})
            .add_production("ModuleHeader", {"ModuleId", "{", "OidComponentList", "}", "DEFINITIONS", "TagDefault", symassign, "BEGIN"})
            .add_production("ModuleHeader", {"ModuleId", "{", "OidComponentList", "}", "DEFINITIONS", symassign, "BEGIN"})

            .add_production("ModuleId", {symuser})
            .add_production("ModuleId", {symid})

            .add_production("OidComponentList", {"OidComponentList", "OidComponent"})
            .add_production("OidComponentList", {"OidComponent"})
            .add_production("OidComponent", {symid, "(", symnum, ")"})

            .add_production("TagDefault", {"EXPLICIT", "TAGS"})
            .add_production("TagDefault", {"IMPLICIT", "TAGS"})
            .add_production("TagDefault", {"AUTOMATIC", "TAGS"})
            .add_production("ExtImplied", {"EXTENSIBILITY", "IMPLIED"})

            .add_production("ModuleBody", {"ExportsClause"})
            .add_production("ModuleBody", {"ImportsClause"})
            .add_production("ModuleBody", {"ExportsClause", "ImportsClause"})
            .add_production("ModuleBody", {"ImportsClause", "ExportsClause"})

            // EXPORTS/IMPORTS
            .add_production("ExportsClause", {"EXPORTS", "SymbolList", ";"})
            .add_production("ExportsClause", {"EXPORTS", "ALL", ";"})

            .add_production("ImportsClause", {"IMPORTS", "SymbolsFromModuleList", ";"})
            .add_production("SymbolsFromModuleList", {"SymbolsFromModuleList", "SymbolsFromModule"})
            .add_production("SymbolsFromModuleList", {"SymbolsFromModule"})
            .add_production("SymbolsFromModule", {"SymbolList", "FROM", "ModuleId"})
            .add_production("SymbolsFromModule", {"SymbolList", "FROM", "ModuleId", "{", "OidComponentList", "}"})

            .add_production("SymbolList", {"SymbolList", ",", "SymbolItem"})
            .add_production("SymbolList", {"SymbolItem"})
            .add_production("SymbolItem", {symuser})
            .add_production("SymbolItem", {symid})
            .add_production("SymbolItem", {symuser, "{", "}"})
            .add_production("SymbolItem", {symid, "{", "}"})

            // Statements
            .add_production("StatementList", {"StatementList", "Statement"})
            .add_production("StatementList", {"Statement"})

            .add_production("Statement", {"Assignment"})
            .add_production("Statement", {"TypeSpec"})
            .add_production("Statement", {"Constraint"})
            .add_production("Statement", {"Field"})
            .add_production("Statement", {"TagPrefix"})
            .add_production("Statement", {"ObjectClassAssignment"})

            // Parameterized Assignment
            .add_production("Assignment", {symuserparamtype, "{", "DummyParamList", "}", symassign, "TypeSpec"})
            .add_production("Assignment", {symuserparamtype, "{", "DummyParamList", "}", symassign, "TypeSpec", "Constraint"})
            .add_production("Assignment", {symuser, "{", "DummyParamList", "}", symassign, "TypeSpec"})
            .add_production("Assignment", {symuser, "{", "DummyParamList", "}", symassign, "TypeSpec", "Constraint"})
            .add_production("Assignment", {symparamtype, "{", "DummyParamList", "}", symassign, "TypeSpec"})
            .add_production("Assignment", {symparamtype, "{", "DummyParamList", "}", symassign, "TypeSpec", "Constraint"})
            // Normal Assignment
            .add_production("Assignment", {"DefinedType", symassign, "TypeSpec"})
            .add_production("Assignment", {"DefinedType", symassign, "TypeSpec", "Constraint"})

            .add_production("DefinedType", {symuser})
            .add_production("DefinedType", {symuserparamtype})
            .add_production("DefinedType", {symparamtype})
            .add_production("DefinedType", {symid})

            .add_production("DummyParamList", {"DummyParamList", ",", "DummyParam"})
            .add_production("DummyParamList", {"DummyParam"})
            .add_production("DummyParam", {symparamtype, ":", symparamvalue})
            .add_production("DummyParam", {symparamtype, ":", symuser})
            .add_production("DummyParam", {symparamtype})
            .add_production("DummyParam", {"TypeSpec", ":", symparamvalue})

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

            .add_production("FieldList", {"FieldList", ",", "Field"})
            .add_production("FieldList", {"Field"})
            .add_production("Field", {symid, "TypeSpec"})
            .add_production("Field", {symid, "TypeSpec", "Constraint"})
            .add_production("Field", {symid, "TypeSpec", "FieldOpt"})
            .add_production("Field", {symid, "TypeSpec", "Constraint", "FieldOpt"})

            .add_production("FieldOpt", {"OPTIONAL"})
            .add_production("FieldOpt", {"DEFAULT", "ValueElement"})
            .add_production("FieldOpt", {"DEFAULT", "{", "}"})

            .add_production("TypeSpec", {"TypeBase"})
            .add_production("TypeSpec", {"EnumType"})
            .add_production("TypeSpec", {"StatementSequence"})
            .add_production("TypeSpec", {"StatementSequenceOf"})
            .add_production("TypeSpec", {"StatementSet"})
            .add_production("TypeSpec", {"StatementSetOf"})
            .add_production("TypeSpec", {"StatementChoice"})

            .add_production("TypeBase", {"SimpleType"})
            .add_production("TypeBase", {"TaggedType"})
            .add_production("TypeBase", {"ReferencedType"})

            // Information Object Class
            .add_production("ObjectClassAssignment", {symparamtype, symassign, "CLASS", "{", "FieldSpecList", "}"})
            .add_production("ObjectClassAssignment", {symparamtype, symassign, "CLASS", "{", "FieldSpecList", "}", "WITH", "SYNTAX", "{", "SyntaxList", "}"})
            .add_production("ObjectClassAssignment", {symuser, symassign, "CLASS", "{", "FieldSpecList", "}"})
            .add_production("ObjectClassAssignment", {symuser, symassign, "CLASS", "{", "FieldSpecList", "}", "WITH", "SYNTAX", "{", "SyntaxList", "}"})

            .add_production("FieldSpecList", {"FieldSpecList", ",", "FieldSpec"})
            .add_production("FieldSpecList", {"FieldSpec"})
            .add_production("FieldSpec", {"&", symid, "TypeSpec"})
            .add_production("FieldSpec", {"&", symid, "TypeSpec", "UNIQUE"})
            .add_production("FieldSpec", {"&", symparamtype})
            .add_production("FieldSpec", {"&", symuser})
            .add_production("FieldSpec", {"&", symid})

            .add_production("SyntaxList", {"SyntaxList", "SyntaxItem"})
            .add_production("SyntaxList", {"SyntaxItem"})
            .add_production("SyntaxItem", {"&", symuser})
            .add_production("SyntaxItem", {"&", symparamtype})
            .add_production("SyntaxItem", {"&", symid})
            .add_production("SyntaxItem", {symuser})
            .add_production("SyntaxItem", {symparamtype})
            .add_production("SyntaxItem", {symid})

            .add_production("ReferencedType", {symid})
            .add_production("ReferencedType", {symuser})
            .add_production("ReferencedType", {symparamtype})
            .add_production("ReferencedType", {symuserparamtype})
            .add_production("ReferencedType", {symuserparamtype, "{", "ActualParamList", "}"})
            .add_production("ReferencedType", {symuser, "{", "ActualParamList", "}"})
            .add_production("ReferencedType", {symparamtype, "{", "ActualParamList", "}"})
            .add_production("ReferencedType", {symid, "{", "ActualParamList", "}"})

            .add_production("ReferencedType", {symparamtype, ".", "&", symid})
            .add_production("ReferencedType", {symparamtype, ".", "&", symuser})
            .add_production("ReferencedType", {symparamtype, ".", "&", symparamtype})
            .add_production("ReferencedType", {symuser, ".", "&", symid})
            .add_production("ReferencedType", {symuser, ".", "&", symuser})
            .add_production("ReferencedType", {symuser, ".", "&", symparamtype})

            .add_production("ActualParamList", {"ActualParamList", ",", "ActualParam"})
            .add_production("ActualParamList", {"ActualParam"})
            .add_production("ActualParam", {"TypeSpec"})
            .add_production("ActualParam", {symparamvalue})
            .add_production("ActualParam", {symparamtype})
            .add_production("ActualParam", {symuser})
            .add_production("ActualParam", {symnum})
            .add_production("ActualParam", {symfp})
            .add_production("ActualParam", {symqs})
            .add_production("ActualParam", {"TRUE"})
            .add_production("ActualParam", {"FALSE"})

            .add_production("TaggedType", {"TagPrefix", "TagSpec", "TypeSpec"})
            .add_production("TaggedType", {"TagPrefix", "TypeSpec"})
            .add_production("TagPrefix", {"[", "TagClass", symnum, "]"})
            .add_production("TagPrefix", {"[", symnum, "]"})
            .add_production("TagClass", {"UNIVERSAL"})
            .add_production("TagClass", {"APPLICATION"})
            .add_production("TagClass", {"PRIVATE"})
            .add_production("TagSpec", {"IMPLICIT"})
            .add_production("TagSpec", {"EXPLICIT"})

            .add_production("EnumType", {"ENUMERATED", "{", "EnumList", "}"})
            .add_production("EnumList", {"EnumList", ",", "EnumItem"})
            .add_production("EnumList", {"EnumItem"})
            .add_production("EnumItem", {symid, "(", symnum, ")"})

            // Simple Built-in Types
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

            // Constraints
            .add_production("Constraint", {"(", "ConstraintExpr", ")"})
            .add_production("ConstraintExpr", {"SubtypeElementSet"})
            .add_production("ConstraintExpr", {"ALL EXCEPT", "SubtypeElementSet"})

            .add_production("SubtypeElementSet", {"SubtypeElementSet", "|", "SubtypeElement"})
            .add_production("SubtypeElementSet", {"SubtypeElementSet", ",", "SubtypeElement"})
            .add_production("SubtypeElementSet", {"SubtypeElementSet", "UNION", "SubtypeElement"})
            .add_production("SubtypeElementSet", {"SubtypeElementSet", "EXCEPT", "SubtypeElement"})
            .add_production("SubtypeElementSet", {"SubtypeElementSet", "SubtypeElement"})
            .add_production("SubtypeElementSet", {"SubtypeElement"})

            .add_production("SubtypeElement", {"SubtypeElement", "^", "PrimaryElement"})
            .add_production("SubtypeElement", {"SubtypeElement", "INTERSECTION", "PrimaryElement"})
            .add_production("SubtypeElement", {"PrimaryElement"})

            .add_production("PrimaryElement", {"ValueElement"})
            .add_production("PrimaryElement", {"ValueElement", "..", "ValueElement"})
            .add_production("PrimaryElement", {"ValueElement", "..", "<", "ValueElement"})
            .add_production("PrimaryElement", {"ValueElement", "<", "..", "ValueElement"})
            .add_production("PrimaryElement", {"ValueElement", "<", "..", "<", "ValueElement"})
            .add_production("PrimaryElement", {"SIZE", "Constraint"})
            .add_production("PrimaryElement", {"FROM", "Constraint"})
            .add_production("PrimaryElement", {"PATTERN", symqs})
            .add_production("PrimaryElement", {"(", "ConstraintExpr", ")"})
            .add_production("PrimaryElement", {"{", symuser, "}"})
            .add_production("PrimaryElement", {"{", symparamtype, "}"})
            .add_production("PrimaryElement", {"{", symparamvalue, "}"})
            .add_production("PrimaryElement", {"{", symparamvalue, "}", "{", "@", symid, "}"})
            .add_production("PrimaryElement", {"{", symparamtype, "}", "{", "@", symid, "}"})
            .add_production("PrimaryElement", {"{", symuser, "}", "{", "@", symid, "}"})

            .add_production("SizeConstraint", {"SIZE", "Constraint"})

            .add_production("ValueElement", {symparamvalue})
            .add_production("ValueElement", {symid})
            .add_production("ValueElement", {symnum})
            .add_production("ValueElement", {symfp})
            .add_production("ValueElement", {symqs})
            .add_production("ValueElement", {"MIN"})
            .add_production("ValueElement", {"MAX"})
            .add_production("ValueElement", {"TRUE"})
            .add_production("ValueElement", {"FALSE"});

        // Terminals
        grammar.add_terminal(symnum)
            .add_terminal(symid)
            .add_terminal(symfp)
            .add_terminal("(")
            .add_terminal(")")
            .add_terminal("[")
            .add_terminal("]")
            .add_terminal("{")
            .add_terminal("}")
            .add_terminal(symassign)
            .add_terminal("<")
            .add_terminal(":")
            .add_terminal(";")
            .add_terminal(",")
            .add_terminal(".")
            .add_terminal("&")
            .add_terminal(symqs)
            .add_terminal("@")
            .add_terminal(symuser)

            .add_terminal("BOOLEAN")
            .add_terminal("INTEGER")
            .add_terminal("BIT STRING")
            .add_terminal("OCTET STRING")
            .add_terminal("NULL")
            .add_terminal("OBJECT IDENTIFIER")
            .add_terminal("REAL")
            .add_terminal("ENUMERATED")
            .add_terminal("UTF8String")
            .add_terminal("RELATIVE-OID")
            .add_terminal("PrintableString")
            .add_terminal("TeletexString")
            .add_terminal("T61String")
            .add_terminal("VideotexString")
            .add_terminal("IA5String")
            .add_terminal("UTCTime")
            .add_terminal("GeneralizedTime")
            .add_terminal("GraphicString")
            .add_terminal("VisibleString")
            .add_terminal("ISO646String")
            .add_terminal("GeneralString")
            .add_terminal("UniversalString")
            .add_terminal("CHARACTER STRING")
            .add_terminal("BMPString")
            .add_terminal("DATE")
            .add_terminal("TIME-OF-DAY")
            .add_terminal("DATE-TIME")
            .add_terminal("DURATION")
            .add_terminal("ANY")

            .add_terminal("SEQUENCE")
            .add_terminal("SET")
            .add_terminal("CHOICE")
            .add_terminal("OF")

            .add_terminal("TRUE")
            .add_terminal("FALSE")
            .add_terminal("UNIVERSAL")
            .add_terminal("APPLICATION")
            .add_terminal("PRIVATE")

            .add_terminal("IMPLICIT")
            .add_terminal("EXPLICIT")
            .add_terminal("DEFAULT")
            .add_terminal("OPTIONAL")

            .add_terminal("UNION")
            .add_terminal("|")
            .add_terminal("INTERSECTION")
            .add_terminal("^")
            .add_terminal("EXCEPT")
            .add_terminal("ALL EXCEPT")
            .add_terminal("SIZE")
            .add_terminal("FROM")
            .add_terminal("PATTERN")
            .add_terminal("MIN")
            .add_terminal("MAX")
            .add_terminal("..")

            .add_terminal("DEFINITIONS")
            .add_terminal("AUTOMATIC")
            .add_terminal("TAGS")
            .add_terminal("BEGIN")
            .add_terminal("END")
            .add_terminal("EXPORTS")
            .add_terminal("IMPORTS")
            .add_terminal("ALL")
            .add_terminal("EXTENSIBILITY")
            .add_terminal("IMPLIED")

            .add_terminal(symuserparamtype)
            .add_terminal(symparamtype)
            .add_terminal(symparamvalue)

            .add_terminal("CLASS")
            .add_terminal("WITH")
            .add_terminal("SYNTAX")
            .add_terminal("UNIQUE")

            .add_terminal("$");

        parser.set_grammar(std::move(grammar));

        _logger->writeln("building GLR parsing table for integrated ASN.1 grammar...");
        ret = parser.learn();
        _logger->writeln("GLR table generation %s", (errorcode_t::success == ret) ? "success" : "failure");
        _test_case.test(ret, __FUNCTION__, "build integrated parsing table");
    }
    __finally2 {}
    return ret;
}

void test_asn1parser(parser_t& parser, const char* text, const char* input) {
    lexical_analyzer lexer;
    prepare_lexer_asn1_usertype(lexer);
    return test_asn1parser(lexer, parser, text, input);
}

void test_asn1parser(lexical_analyzer& lexer, parser_t& parser, const char* text, const char* input) {
    return_t ret = errorcode_t::success;
    std::vector<parser_token> tokens;

    lexical_context context;

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

parser_t& get_lalr_parser_asn1notation() {
    static lalr_parser parser;
    static int lalr_parser_ready = 0;
    if (0 == lalr_parser_ready) {
        prepare_asn1notation_grammar(parser);
        lalr_parser_ready = 1;
    }
    return parser;
}

parser_t& get_glr_parser_asn1parameterized() {
    static glr_parser parser;
    static int glr_parser_ready = 0;
    if (0 == glr_parser_ready) {
        prepare_asn1parameterized_grammar(parser);
        glr_parser_ready = 1;
    }
    return parser;
}

parser_t& get_glr_parser_asn1() {
    static glr_parser parser;
    static int glr_parser_ready = 0;
    if (0 == glr_parser_ready) {
        prepare_asn1_grammar(parser);
        glr_parser_ready = 1;
    }
    return parser;
}
