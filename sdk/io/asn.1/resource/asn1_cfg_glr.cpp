/* vim: set tabstop=4 parser_action_t::shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_cfg_glr.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * see README.md
 */

#include <hotplace/sdk/io/asn.1/asn1_resource.hpp>
#include <hotplace/sdk/io/parser/glr_parser.hpp>
#include <hotplace/sdk/io/parser/parser_resource.hpp>

namespace hotplace {
namespace io {

return_t prepare_glr_parser_asn1(parser_t& parser);
return_t import_glr_parser_asn1(glr_parser& parser);

parser_t& get_glr_parser_asn1_by_build() {
    static glr_parser parser;
    static const return_t ready = prepare_glr_parser_asn1(parser);
    (void)ready;
    return parser;
}

parser_t& get_glr_parser_asn1_by_import() {
    static glr_parser parser;
    static const return_t ready = import_glr_parser_asn1(parser);
    (void)ready;
    return parser;
}

return_t import_glr_parser_asn1(glr_parser& parser) { return parser.import(asn1_allin1_productions, asn1_allin1_action_table, asn1_allin1_goto_table); }

/**
 * CFG for ASN.1 Module, Notation, Parameterized, Information Object Class
 * - Extension Marker Version 1 and 2 in progress
 *
 * 1. Single Top-Level Entry Point
 * 2. Resolving Rule Cycling and Recursive Ambiguity Issues
 * - FieldList and EnumList are structured without an ExtensionMarker.
 * - Handling ExtensionMarker in SequenceTypeSpec, ChoiceTypeSpec, and EnumTypeSpec
 */
return_t prepare_glr_parser_asn1(parser_t& parser) {
    auto resource = parser_resource::get_instance();

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
    // 1. Single Top-Level Entry Point & Module Structure
    grammar
        .add_production("S'", {"Start"})

        .add_production("Start", {"ModuleDefinitionList"})
        .add_production("Start", {"ModuleDefinition"})
        .add_production("Start", {"StatementList"})

        .add_production("ModuleDefinitionList", {"ModuleDefinitionList", "ModuleDefinition"})
        .add_production("ModuleDefinitionList", {"ModuleDefinition"})

        // Module Definition
        .add_production("ModuleDefinition", {"ModuleBegin", "SymbolClauses", "StatementList", "ModuleEnd"})
        .add_production("ModuleDefinition", {"ModuleBegin", "StatementList", "ModuleEnd"})
        .add_production("ModuleDefinition", {"ModuleBegin", "ModuleEnd"})

        .add_production("ModuleBegin", {"ModuleId", "DEFINITIONS", "TagDefault", "ExtImplied", symassign, "BEGIN"})
        .add_production("ModuleBegin", {"ModuleId", "DEFINITIONS", "TagDefault", symassign, "BEGIN"})
        .add_production("ModuleBegin", {"ModuleId", "DEFINITIONS", symassign, "BEGIN"})
        .add_production("ModuleBegin", {"ModuleId", "{", "OidComponentList", "}", "DEFINITIONS", "TagDefault", "ExtImplied", symassign, "BEGIN"})
        .add_production("ModuleBegin", {"ModuleId", "{", "OidComponentList", "}", "DEFINITIONS", "TagDefault", symassign, "BEGIN"})
        .add_production("ModuleBegin", {"ModuleId", "{", "OidComponentList", "}", "DEFINITIONS", symassign, "BEGIN"})
        .add_production("ModuleEnd", {"END"})

        .add_production("ModuleId", {symid})

        .add_production("OidComponentList", {"OidComponentList", "OidComponent"})
        .add_production("OidComponentList", {"OidComponent"})
        .add_production("OidComponent", {symid, "(", symnum, ")"})

        .add_production("TagDefault", {"EXPLICIT", "TAGS"})
        .add_production("TagDefault", {"IMPLICIT", "TAGS"})
        .add_production("TagDefault", {"AUTOMATIC", "TAGS"})
        .add_production("ExtImplied", {"EXTENSIBILITY", "IMPLIED"})

        .add_production("SymbolClauses", {"ExportsClause"})
        .add_production("SymbolClauses", {"ImportsClause"})
        .add_production("SymbolClauses", {"ExportsClause", "ImportsClause"})
        .add_production("SymbolClauses", {"ImportsClause", "ExportsClause"})

        // EXPORTS / IMPORTS
        .add_production("ExportsClause", {"EXPORTS", "SymbolList", ";"})
        .add_production("ExportsClause", {"EXPORTS", "ALL", ";"})

        .add_production("ImportsClause", {"IMPORTS", "SymbolsFromModuleList", ";"})
        .add_production("SymbolsFromModuleList", {"SymbolsFromModuleList", "SymbolsFromModule"})
        .add_production("SymbolsFromModuleList", {"SymbolsFromModule"})
        .add_production("SymbolsFromModule", {"SymbolList", "FROM", "ModuleId"})
        .add_production("SymbolsFromModule", {"SymbolList", "FROM", "ModuleId", "{", "OidComponentList", "}"})

        .add_production("SymbolList", {"SymbolList", ",", "SymbolItem"})
        .add_production("SymbolList", {"SymbolItem"})
        .add_production("SymbolItem", {symuserparamtype})
        .add_production("SymbolItem", {symuserparamtype, "{", "}"})
        .add_production("SymbolItem", {symuser})
        .add_production("SymbolItem", {symuser, "{", "}"})

        // 2. Statements & Assignments
        .add_production("StatementList", {"StatementList", "Statement"})
        .add_production("StatementList", {"Statement"})

        .add_production("Statement", {"Assignment"})
        .add_production("Statement", {"TypeSpec"})
        .add_production("Statement", {"Constraint"})
        .add_production("Statement", {"Field"})
        .add_production("Statement", {"TagPrefix"})
        .add_production("Statement", {"ObjectClassAssignment"})
        .add_production("Statement", {"ObjectAssignment"})

        // Parameterized Assignment
        .add_production("Assignment", {symuserparamtype, "{", "TemplateParamList", "}", symassign, "TypeSpec"})
        .add_production("Assignment", {symuserparamtype, "{", "TemplateParamList", "}", symassign, "TypeSpec", "Constraint"})
        // Standard Assignment
        .add_production("Assignment", {"DefinedType", symassign, "TypeSpec"})
        .add_production("Assignment", {"DefinedType", symassign, "TypeSpec", "Constraint"})

        .add_production("DefinedType", {symuser})
        .add_production("DefinedType", {symuserparamtype})

        .add_production("TemplateParamList", {"TemplateParamList", ",", "TemplateParam"})
        .add_production("TemplateParamList", {"TemplateParam"})
        .add_production("TemplateParam", {symparamtype, ":", symparamvalue})
        .add_production("TemplateParam", {symparamtype, ":", symuser})
        .add_production("TemplateParam", {symparamtype})
        .add_production("TemplateParam", {"TypeSpec", ":", symparamvalue})

        // 3. Type Specifications (Constructed, Simple, Tagged, Referenced)
        .add_production("TypeSpec", {"SimpleTypeSpec"})
        .add_production("TypeSpec", {"TaggedTypeSpec"})
        .add_production("TypeSpec", {"ReferencedTypeSpec"})
        .add_production("TypeSpec", {"ClassFieldTypeSpec"})
        .add_production("TypeSpec", {"EnumTypeSpec"})
        .add_production("TypeSpec", {"SequenceTypeSpec"})
        .add_production("TypeSpec", {"SequenceOfTypeSpec"})
        .add_production("TypeSpec", {"SetTypeSpec"})
        .add_production("TypeSpec", {"SetOfTypeSpec"})
        .add_production("TypeSpec", {"ChoiceTypeSpec"})

        // FieldList rules for SEQUENCE / SET / CHOICE
        .add_production("FieldList", {"FieldList", ",", "Field"})
        .add_production("FieldList", {"Field"})

        // Constructed Types (SEQUENCE, SET, CHOICE)
        .add_production("SequenceTypeSpec", {"SEQUENCE", "Constraint", "{", "FieldList", ",", "ExtensionMarker", ",", "FieldList", "}"})
        .add_production("SequenceTypeSpec", {"SEQUENCE", "{", "FieldList", ",", "ExtensionMarker", ",", "FieldList", "}"})
        .add_production("SequenceTypeSpec", {"SEQUENCE", "Constraint", "{", "FieldList", ",", "ExtensionMarker", "}"})
        .add_production("SequenceTypeSpec", {"SEQUENCE", "{", "FieldList", ",", "ExtensionMarker", "}"})
        .add_production("SequenceTypeSpec", {"SEQUENCE", "Constraint", "{", "FieldList", "}"})
        .add_production("SequenceTypeSpec", {"SEQUENCE", "{", "FieldList", "}"})
        .add_production("SequenceTypeSpec", {"SEQUENCE", "Constraint", "{", "}"})
        .add_production("SequenceTypeSpec", {"SEQUENCE", "{", "}"})

        .add_production("SequenceOfTypeSpec", {"SEQUENCE", "SizeConstraint", "OF", "TypeSpec"})
        .add_production("SequenceOfTypeSpec", {"SEQUENCE", "Constraint", "OF", "TypeSpec"})
        .add_production("SequenceOfTypeSpec", {"SEQUENCE", "OF", "TypeSpec"})

        .add_production("SetTypeSpec", {"SET", "Constraint", "{", "FieldList", "}"})
        .add_production("SetTypeSpec", {"SET", "{", "FieldList", "}"})
        .add_production("SetTypeSpec", {"SET", "Constraint", "{", "}"})
        .add_production("SetTypeSpec", {"SET", "{", "}"})

        .add_production("SetOfTypeSpec", {"SET", "SizeConstraint", "OF", "TypeSpec"})
        .add_production("SetOfTypeSpec", {"SET", "Constraint", "OF", "TypeSpec"})
        .add_production("SetOfTypeSpec", {"SET", "OF", "TypeSpec"})

        .add_production("ChoiceTypeSpec", {"CHOICE", "Constraint", "{", "FieldList", ",", "ExtensionMarker", ",", "FieldList", "}"})
        .add_production("ChoiceTypeSpec", {"CHOICE", "{", "FieldList", ",", "ExtensionMarker", ",", "FieldList", "}"})
        .add_production("ChoiceTypeSpec", {"CHOICE", "Constraint", "{", "FieldList", ",", "ExtensionMarker", "}"})
        .add_production("ChoiceTypeSpec", {"CHOICE", "{", "FieldList", ",", "ExtensionMarker", "}"})
        .add_production("ChoiceTypeSpec", {"CHOICE", "Constraint", "{", "FieldList", "}"})
        .add_production("ChoiceTypeSpec", {"CHOICE", "{", "FieldList", "}"})
        .add_production("ChoiceTypeSpec", {"CHOICE", "Constraint", "{", "}"})
        .add_production("ChoiceTypeSpec", {"CHOICE", "{", "}"})

        .add_production("NamedTypeSpec", {symid, "TypeSpec"})

        .add_production("Field", {"NamedTypeSpec"})
        .add_production("Field", {"NamedTypeSpec", "Constraint"})
        .add_production("Field", {"NamedTypeSpec", "FieldSpecifier"})
        .add_production("Field", {"NamedTypeSpec", "Constraint", "FieldSpecifier"})

        .add_production("FieldSpecifier", {"OPTIONAL"})
        .add_production("FieldSpecifier", {"DEFAULT", "ValueElement"})
        .add_production("FieldSpecifier", {"DEFAULT", "{", "}"})

        // Referenced Types & Parameterized Template Arguments
        .add_production("Identifier", {symuser})
        .add_production("Identifier", {symid})

        .add_production("ReferencedTypeSpec", {"Identifier"})
        .add_production("ReferencedTypeSpec", {symparamtype})
        .add_production("ReferencedTypeSpec", {symuserparamtype})
        .add_production("ReferencedTypeSpec", {symuserparamtype, "{", "TemplateArgumentList", "}"})
        .add_production("ReferencedTypeSpec", {symuser, "{", "TemplateArgumentList", "}"})
        .add_production("ReferencedTypeSpec", {symparamtype, "{", "TemplateArgumentList", "}"})
        .add_production("ReferencedTypeSpec", {symid, "{", "TemplateArgumentList", "}"})

        .add_production("TemplateArgumentList", {"TemplateArgumentList", ",", "TemplateArgument"})
        .add_production("TemplateArgumentList", {"TemplateArgument"})
        .add_production("TemplateArgument", {"TypeSpec"})
        .add_production("TemplateArgument", {symparamvalue})
        .add_production("TemplateArgument", {symparamtype})
        .add_production("TemplateArgument", {symuser})
        .add_production("TemplateArgument", {symnum})
        .add_production("TemplateArgument", {symfp})
        .add_production("TemplateArgument", {symqs})
        .add_production("TemplateArgument", {"TRUE"})
        .add_production("TemplateArgument", {"FALSE"})

        // Tagged Specifications
        .add_production("TaggedTypeSpec", {"TagPrefix", "TagSpec", "TypeSpec"})
        .add_production("TaggedTypeSpec", {"TagPrefix", "TypeSpec"})
        .add_production("TagPrefix", {"[", "TagClass", symnum, "]"})
        .add_production("TagPrefix", {"[", symnum, "]"})
        .add_production("TagClass", {"UNIVERSAL"})
        .add_production("TagClass", {"APPLICATION"})
        .add_production("TagClass", {"PRIVATE"})
        .add_production("TagSpec", {"IMPLICIT"})
        .add_production("TagSpec", {"EXPLICIT"})

        // Enum Specifications & Extensions
        .add_production("EnumTypeSpec", {"ENUMERATED", "{", "EnumList", ",", "ExtensionMarker", ",", "EnumList", "}"})
        .add_production("EnumTypeSpec", {"ENUMERATED", "{", "EnumList", ",", "ExtensionMarker", "}"})
        .add_production("EnumTypeSpec", {"ENUMERATED", "{", "EnumList", "}"})

        // EnumList rules for ENUMERATED
        .add_production("EnumList", {"EnumList", ",", "EnumItem"})
        .add_production("EnumList", {"EnumItem"})

        .add_production("EnumItem", {symid, "(", symnum, ")"})

        .add_production("ExtensionMarker", {"..."})

        // Built-in Simple Types
        .add_production("SimpleTypeSpec", {"BOOLEAN"})
        .add_production("SimpleTypeSpec", {"INTEGER"})
        .add_production("SimpleTypeSpec", {"INTEGER", "{", "EnumList", "}"})
        .add_production("SimpleTypeSpec", {"BIT STRING"})
        .add_production("SimpleTypeSpec", {"BIT STRING", "{", "EnumList", "}"})
        .add_production("SimpleTypeSpec", {"OCTET STRING"})
        .add_production("SimpleTypeSpec", {"NULL"})
        .add_production("SimpleTypeSpec", {"OBJECT IDENTIFIER"})
        .add_production("SimpleTypeSpec", {"REAL"})
        .add_production("SimpleTypeSpec", {"UTF8String"})
        .add_production("SimpleTypeSpec", {"RELATIVE-OID"})
        .add_production("SimpleTypeSpec", {"TIME"})
        .add_production("SimpleTypeSpec", {"NumericString"})
        .add_production("SimpleTypeSpec", {"PrintableString"})
        .add_production("SimpleTypeSpec", {"TeletexString"})
        .add_production("SimpleTypeSpec", {"T61String"})
        .add_production("SimpleTypeSpec", {"VideotexString"})
        .add_production("SimpleTypeSpec", {"IA5String"})
        .add_production("SimpleTypeSpec", {"UTCTime"})
        .add_production("SimpleTypeSpec", {"GeneralizedTime"})
        .add_production("SimpleTypeSpec", {"GraphicString"})
        .add_production("SimpleTypeSpec", {"VisibleString"})
        .add_production("SimpleTypeSpec", {"ISO646String"})
        .add_production("SimpleTypeSpec", {"GeneralString"})
        .add_production("SimpleTypeSpec", {"UniversalString"})
        .add_production("SimpleTypeSpec", {"CHARACTER STRING"})
        .add_production("SimpleTypeSpec", {"BMPString"})
        .add_production("SimpleTypeSpec", {"DATE"})
        .add_production("SimpleTypeSpec", {"TIME-OF-DAY"})
        .add_production("SimpleTypeSpec", {"DATE-TIME"})
        .add_production("SimpleTypeSpec", {"DURATION"})
        .add_production("SimpleTypeSpec", {"ANY"})

        // 4. Information Object Class & Field Reference
        .add_production("ObjectClassAssignment", {symparamtype, symassign, "CLASS", "{", "FieldSpecList", "}"})
        .add_production("ObjectClassAssignment", {symparamtype, symassign, "CLASS", "{", "FieldSpecList", "}", "WITH", "SYNTAX", "{", "SyntaxList", "}"})
        .add_production("ObjectClassAssignment", {symuser, symassign, "CLASS", "{", "FieldSpecList", "}"})
        .add_production("ObjectClassAssignment", {symuser, symassign, "CLASS", "{", "FieldSpecList", "}", "WITH", "SYNTAX", "{", "SyntaxList", "}"})

        .add_production("FieldSpecList", {"FieldSpecList", ",", "FieldSpec"})
        .add_production("FieldSpecList", {"FieldSpec"})
        .add_production("FieldSpec", {"&", "Field"})
        .add_production("FieldSpec", {"&", "Field", "UNIQUE"})
        .add_production("FieldSpec", {"&", symparamtype})
        .add_production("FieldSpec", {"&", "Identifier"})

        .add_production("SyntaxList", {"SyntaxList", "SyntaxItem"})
        .add_production("SyntaxList", {"SyntaxItem"})
        .add_production("SyntaxItem", {"&", "Identifier"})
        .add_production("SyntaxItem", {"&", symparamtype})
        .add_production("SyntaxItem", {"Identifier"})
        .add_production("SyntaxItem", {symparamtype})

        .add_production("ClassFieldTypeSpec", {symparamtype, "ClassFieldReference"})
        .add_production("ClassFieldTypeSpec", {symuser, "ClassFieldReference"})
        .add_production("ClassFieldReference", {".", "&", "Identifier"})
        .add_production("ClassFieldReference", {".", "&", symparamtype})

        .add_production("ObjectAssignment", {symid, symuser, symassign, "{", "SettingList", "}"})
        .add_production("ObjectAssignment", {symid, symparamtype, symassign, "{", "SettingList", "}"})
        .add_production("SettingList", {"SettingList", "SettingItem"})
        .add_production("SettingList", {"SettingItem"})

        .add_production("SettingItem", {"Identifier", "ValueElement"})
        .add_production("SettingItem", {"Identifier", "TypeSpec"})

        // 5. Constraints & Values
        .add_production("Constraint", {"(", "ConstraintExpr", ")"})
        .add_production("ConstraintExpr", {"SubtypeElementSet"})
        .add_production("ConstraintExpr", {"ALL EXCEPT", "SubtypeElementSet"})

        .add_production("SubtypeElementSet", {"SubtypeElementSet", "UnionOperation", "SubtypeElement"})
        .add_production("SubtypeElementSet", {"SubtypeElementSet", "EXCEPT", "SubtypeElement"})
        .add_production("SubtypeElementSet", {"SubtypeElementSet", "IntersectOperation", "SubtypeElement"})
        .add_production("SubtypeElementSet", {"SubtypeElementSet", "SubtypeElement"})
        .add_production("SubtypeElementSet", {"SubtypeElement"})

        .add_production("SubtypeElement", {"SubtypeElement", "IntersectOperation", "PrimaryElement"})
        .add_production("SubtypeElement", {"PrimaryElement"})

        .add_production("UnionOperation", {","})  // MultiSize ::= OCTET STRING (SIZE (1..10, 20..30))
        .add_production("UnionOperation", {"|"})
        .add_production("UnionOperation", {"UNION"})
        .add_production("IntersectOperation", {"^"})
        .add_production("IntersectOperation", {"INTERSECTION"})
        .add_production("IntersectOperation", {"INTERSECT"})

        .add_production("PrimaryElement", {"ValueElement"})
        .add_production("PrimaryElement", {"ValueElement", "..", "ValueElement"})
        .add_production("PrimaryElement", {"ValueElement", "..", "<", "ValueElement"})
        .add_production("PrimaryElement", {"ValueElement", "<", "..", "ValueElement"})
        .add_production("PrimaryElement", {"ValueElement", "<", "..", "<", "ValueElement"})
        .add_production("PrimaryElement", {"SIZE", "Constraint"})
        .add_production("PrimaryElement", {"FROM", "Constraint"})
        .add_production("PrimaryElement", {"PATTERN", symqs})
        .add_production("PrimaryElement", {"(", "ConstraintExpr", ")"})
        .add_production("PrimaryElement", {"ObjectSetSpec"})
        .add_production("PrimaryElement", {"ObjectSetSpec", "RelationalConstraint"})

        .add_production("ObjectSetSpec", {"{", symuser, "}"})
        .add_production("ObjectSetSpec", {"{", symparamtype, "}"})
        .add_production("ObjectSetSpec", {"{", symparamvalue, "}"})

        .add_production("RelationalConstraint", {"{", "@", symid, "}"})

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

    // 6. Terminals Registration
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
        .add_terminal("NumericString")
        .add_terminal("PrintableString")
        .add_terminal("T61String")
        .add_terminal("TeletexString")
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
        .add_terminal("^")
        .add_terminal("INTERSECTION")
        .add_terminal("INTERSECT")
        .add_terminal("EXCEPT")
        .add_terminal("ALL EXCEPT")
        .add_terminal("SIZE")
        .add_terminal("FROM")
        .add_terminal("PATTERN")
        .add_terminal("MIN")
        .add_terminal("MAX")
        .add_terminal("..")
        .add_terminal("...")

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

    // _logger->writeln("building GLR parsing table for integrated ASN.1 grammar...");
    return parser.learn();
    // _logger->writeln("GLR table generation %s", (errorcode_t::success == ret) ? "success" : "failure");
    // _test_case.test(ret, __FUNCTION__, "GLR parser - ASSN.1 for All-in-One (build parsing table)");
}

}  // namespace io
}  // namespace hotplace
