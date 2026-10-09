/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
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

#include <hotplace/sdk/io/asn.1/asn1_advisor.hpp>
#include <hotplace/sdk/io/parser/binary_parsing_table.hpp>
#include <hotplace/sdk/io/parser/glr_parser.hpp>
#include <hotplace/sdk/io/parser/parser_resource.hpp>

namespace hotplace {
namespace io {

parser_t& asn1_advisor::get_parser_by_build() {
    if (false == _glr_parser_by_build.ready()) {
        prepare_glr_parser(_glr_parser_by_build);
    }
    return _glr_parser_by_build;
}

parser_t& asn1_advisor::get_parser_by_import() {
    if (false == _glr_parser_by_import.ready()) {
        import_glr_parser(_glr_parser_by_import);
    }
    return _glr_parser_by_import;
}

/**
 * CFG for ASN.1 Module, Notation, Parameterized, Information Object Class
 * - Extension Marker Version 1 and 2 in progress
 *
 * 1. Single Top-Level Entry Point
 * 2. Resolving Rule Cycling and Recursive Ambiguity Issues
 * - ComponentTypeList and Enumerations are structured without an ExtensionMarker.
 * - Handling ExtensionMarker in SequenceTypeSpec, ChoiceTypeSpec, and EnumeratedType
 */
return_t asn1_advisor::prepare_glr_parser(parser_t& parser) {
    auto resource = parser_resource::get_instance();

    auto symid = resource->nameof(token_identifier);     // "identifier"
    auto symnum = resource->nameof(token_number);        // "number"
    auto symfp = resource->nameof(token_floatingpoint);  // "floatingpoint"
    auto symqs = resource->nameof(token_quot_string);    // "quot_string"
    auto symuser = resource->nameof(token_usertype);     // "usertype"
    auto symassign = resource->nameof(token_assign);     // "::="
    auto symhexstr = resource->nameof(token_hexstring);  // "hex_string"

    cfg_grammar grammar;
    grammar
        // rule revision (.ptb file revision)
        .set_revision(2)
        // 1. Entry Points
        .add_production("S'", {"Start"})
        .add_production("Start", {"ModuleStatementList"})
        .add_production("Start", {"StatementList"})
        .add_production("Start", {"ComponentType"})
        .add_production("Start", {"Type"})
        .add_production("Start", {"TagSpec"})

        .add_production("ModuleStatementList", {"ModuleStatementList", "ModuleStatement"})
        .add_production("ModuleStatementList", {"ModuleStatement"})
        .add_production("ModuleStatement", {"ModuleDefinition"})
        .add_production("ModuleStatement", {"Statement"})

        // 2. Module Definition
        .add_production("ModuleDefinition", {"ModuleIdentifier", "DEFINITIONS", "TagDefault", "ExtensionDefault", symassign, "BEGIN", "ModuleBody", "END"})
        .add_production("ModuleDefinition", {"ModuleIdentifier", "DEFINITIONS", "TagDefault", symassign, "BEGIN", "ModuleBody", "END"})
        .add_production("ModuleDefinition", {"ModuleIdentifier", "DEFINITIONS", symassign, "BEGIN", "ModuleBody", "END"})

        .add_production("ModuleIdentifier", {symid})
        .add_production("ModuleIdentifier", {symid, "{", "DefinitiveOidComponentList", "}"})
        .add_production("DefinitiveOidComponentList", {"DefinitiveOidComponentList", "DefinitiveObjIdComponent"})
        .add_production("DefinitiveOidComponentList", {"DefinitiveObjIdComponent"})
        .add_production("DefinitiveObjIdComponent", {symid, "(", symnum, ")"})
        .add_production("DefinitiveObjIdComponent", {symnum})

        .add_production("TagDefault", {"EXPLICIT", "TAGS"})
        .add_production("TagDefault", {"IMPLICIT", "TAGS"})
        .add_production("TagDefault", {"AUTOMATIC", "TAGS"})
        .add_production("ExtensionDefault", {"EXTENSIBILITY", "IMPLIED"})

        .add_production("ModuleBody", {"Exports", "Imports", "AssignmentList"})
        .add_production("ModuleBody", {"Exports", "AssignmentList"})
        .add_production("ModuleBody", {"Imports", "AssignmentList"})
        .add_production("ModuleBody", {"AssignmentList"})
        .add_production("ModuleBody", {})

        .add_production("Exports", {"EXPORTS", "SymbolList", ";"})
        .add_production("Exports", {"EXPORTS", "ALL", ";"})
        .add_production("Imports", {"IMPORTS", "SymbolsFromModuleList", ";"})
        .add_production("SymbolsFromModuleList", {"SymbolsFromModuleList", "SymbolsFromModule"})
        .add_production("SymbolsFromModuleList", {"SymbolsFromModule"})
        .add_production("SymbolsFromModule", {"SymbolList", "FROM", "ModuleIdentifier"})

        .add_production("SymbolList", {"SymbolList", ",", "Symbol"})
        .add_production("SymbolList", {"Symbol"})
        .add_production("Symbol", {"TypeIdentifier"})
        .add_production("Symbol", {"TypeIdentifier", "{", "}"})

        // 3. Statements & Assignments
        .add_production("StatementList", {"StatementList", "Statement"})
        .add_production("StatementList", {"Statement"})
        .add_production("Statement", {"Assignment"})

        .add_production("AssignmentList", {"AssignmentList", "Assignment"})
        .add_production("AssignmentList", {"Assignment"})

        .add_production("Assignment", {"TypeAssignment"})
        .add_production("Assignment", {"ValueAssignment"})
        .add_production("Assignment", {"ObjectClassAssignment"})
        .add_production("Assignment", {"InformationObjectAssignment"})
        .add_production("Assignment", {"ParameterizedAssignment"})

        .add_production("ParameterizedAssignment", {"ParameterizedTypeAssignment"})
        .add_production("ParameterizedAssignment", {"ParameterizedValueAssignment"})

        // Parameterized Type & Value Assignment (ITU-T X.683)
        .add_production("ParameterizedTypeAssignment", {symid, "{", "ParameterList", "}", symassign, "Type"})
        .add_production("ParameterizedTypeAssignment", {symid, "{", "ParameterList", "}", symassign, "Type", "Constraint"})
        .add_production("ParameterizedTypeAssignment", {symuser, "{", "ParameterList", "}", symassign, "Type"})
        .add_production("ParameterizedTypeAssignment", {symuser, "{", "ParameterList", "}", symassign, "Type", "Constraint"})

        .add_production("ParameterizedValueAssignment", {symid, "{", "ParameterList", "}", "Type", symassign, "ValueElement"})
        .add_production("ParameterizedValueAssignment", {symid, "{", "ParameterList", "}", "Type", symassign, "{", "ValueElementList", "}"})
        .add_production("ParameterizedValueAssignment", {symuser, "{", "ParameterList", "}", "Type", symassign, "ValueElement"})
        .add_production("ParameterizedValueAssignment", {symuser, "{", "ParameterList", "}", "Type", symassign, "{", "ValueElementList", "}"})

        .add_production("TypeAssignment", {"DefinedType", symassign, "Type"})
        .add_production("TypeAssignment", {"DefinedType", symassign, "Type", "Constraint"})

        .add_production("ValueAssignment", {symid, "Type", symassign, "ValueElement"})
        .add_production("ValueAssignment", {symid, "Type", symassign, "{", "ValueElementList", "}"})

        .add_production("ValueElementList", {"ValueElementList", ",", "ValueElement"})
        .add_production("ValueElementList", {"ValueElementList", "ValueElement"})
        .add_production("ValueElementList", {"ValueElement"})

        .add_production("DefinedType", {symuser})
        .add_production("DefinedType", {symid})

        // Parameter List
        .add_production("ParameterList", {"ParameterList", ",", "Parameter"})
        .add_production("ParameterList", {"Parameter"})
        .add_production("Parameter", {"TypeIdentifier"})
        .add_production("Parameter", {"Type"})
        .add_production("Parameter", {symid, ":", symid})
        .add_production("Parameter", {symuser, ":", "TypeIdentifier"})
        .add_production("Parameter", {"Type", ":", "TypeIdentifier"})
        .add_production("Parameter", {"Type", ":", symid})

        // 4. Type Specifications
        .add_production("Type", {"SimpleTypeSpec"})
        .add_production("Type", {"TaggedTypeSpec"})
        .add_production("Type", {"ReferencedTypeSpec"})
        .add_production("Type", {"ObjectClassFieldType"})
        .add_production("Type", {"EnumeratedType"})
        .add_production("Type", {"SequenceTypeSpec"})
        .add_production("Type", {"SequenceOfTypeSpec"})
        .add_production("Type", {"SetTypeSpec"})
        .add_production("Type", {"SetOfTypeSpec"})
        .add_production("Type", {"ChoiceTypeSpec"})
        .add_production("Type", {"ParameterizedType"})

        .add_production("TypeIdentifier", {symuser})
        .add_production("TypeIdentifier", {symid})

        .add_production("ReferencedTypeSpec", {"TypeIdentifier"})

        .add_production("ParameterizedType", {symid, "{", "ActualParameterList", "}"})
        .add_production("ParameterizedType", {"TypeIdentifier", "{", "ActualParameterList", "}"})

        .add_production("NamedType", {symid, "Type"})
        .add_production("ComponentType", {"NamedType"})
        .add_production("ComponentType", {"NamedType", "Constraints"})
        .add_production("ComponentType", {"NamedType", "OptionalitySpec"})
        .add_production("ComponentType", {"NamedType", "Constraints", "OptionalitySpec"})

        .add_production("ComponentTypeList", {"ComponentTypeList", ",", "ComponentType"})
        .add_production("ComponentTypeList", {"ComponentType"})

        .add_production("ExtensionAdditions", {",", "ExtensionMarker"})
        .add_production("ExtensionAdditions", {",", "ExtensionMarker", ",", "ComponentTypeList"})
        .add_production("ExtensionAdditions", {",", "ExtensionMarker", ",", "ExtensionMarker", ",", "ComponentTypeList"})

        .add_production("ComponentTypeLists", {"Constraint", "{", "ComponentTypeList", "ExtensionAdditions", "}"})
        .add_production("ComponentTypeLists", {"{", "ComponentTypeList", "ExtensionAdditions", "}"})
        .add_production("ComponentTypeLists", {"Constraint", "{", "ComponentTypeList", "}"})
        .add_production("ComponentTypeLists", {"{", "ComponentTypeList", "}"})
        .add_production("ComponentTypeLists", {"Constraint", "{", "}"})
        .add_production("ComponentTypeLists", {"{", "}"})

        .add_production("SequenceTypeSpec", {"SEQUENCE", "ComponentTypeLists"})
        .add_production("SetTypeSpec", {"SET", "ComponentTypeLists"})
        .add_production("ChoiceTypeSpec", {"CHOICE", "ComponentTypeLists"})

        .add_production("SequenceOfTypeSpec", {"SEQUENCE", "SizeConstraint", "OF", "Type"})
        .add_production("SequenceOfTypeSpec", {"SEQUENCE", "Constraint", "OF", "Type"})
        .add_production("SequenceOfTypeSpec", {"SEQUENCE", "OF", "Type"})

        .add_production("SetOfTypeSpec", {"SET", "SizeConstraint", "OF", "Type"})
        .add_production("SetOfTypeSpec", {"SET", "Constraint", "OF", "Type"})
        .add_production("SetOfTypeSpec", {"SET", "OF", "Type"})

        .add_production("OptionalitySpec", {"OPTIONAL"})
        .add_production("OptionalitySpec", {"DEFAULT", "ValueElement"})
        .add_production("OptionalitySpec", {"DEFAULT", "{", "}"})

        .add_production("ActualParameterList", {"ActualParameterList", ",", "ActualParameter"})
        .add_production("ActualParameterList", {"ActualParameter"})
        .add_production("ActualParameter", {"Type"})
        .add_production("ActualParameter", {"ValueElement"})
        .add_production("ActualParameter", {"{", "DefinitiveOidComponentList", "}"})
        .add_production("ActualParameter", {"{", "ValueElementList", "}"})
        .add_production("ActualParameter", {"{", "}"})
        .add_production("ActualParameter", {"TypeIdentifier"})

        .add_production("TaggedTypeSpec", {"TagSpec", "IMPLICIT", "Type"})
        .add_production("TaggedTypeSpec", {"TagSpec", "EXPLICIT", "Type"})
        .add_production("TaggedTypeSpec", {"TagSpec", "Type"})

        .add_production("TagSpec", {"[", "UNIVERSAL", symnum, "]"})
        .add_production("TagSpec", {"[", "APPLICATION", symnum, "]"})
        .add_production("TagSpec", {"[", "PRIVATE", symnum, "]"})
        .add_production("TagSpec", {"[", symnum, "]"})

        .add_production("EnumeratedType", {"ENUMERATED", "{", "Enumerations", "ExtensionAdditionEnumeration", "}"})
        .add_production("EnumeratedType", {"ENUMERATED", "{", "Enumerations", "}"})
        .add_production("ExtensionAdditionEnumeration", {",", "ExtensionMarker"})
        .add_production("ExtensionAdditionEnumeration", {",", "ExtensionMarker", ",", "Enumerations"})

        .add_production("Enumerations", {"Enumerations", ",", "Enumeration"})
        .add_production("Enumerations", {"Enumeration"})
        .add_production("Enumeration", {symid, "(", symnum, ")"})
        .add_production("Enumeration", {symid})
        .add_production("ExtensionMarker", {"..."})

        // Simple Built-in Types
        .add_production("SimpleTypeSpec", {"BOOLEAN"})
        .add_production("SimpleTypeSpec", {"INTEGER"})
        .add_production("SimpleTypeSpec", {"INTEGER", "{", "Enumerations", "}"})
        .add_production("SimpleTypeSpec", {"BIT STRING"})
        .add_production("SimpleTypeSpec", {"BIT STRING", "{", "Enumerations", "}"})
        .add_production("SimpleTypeSpec", {"OCTET STRING"})
        .add_production("SimpleTypeSpec", {"NULL"})
        .add_production("SimpleTypeSpec", {"OBJECT IDENTIFIER"})
        .add_production("SimpleTypeSpec", {"REAL"})
        .add_production("SimpleTypeSpec", {"UTF8String"})
        .add_production("SimpleTypeSpec", {"RELATIVE-OID"})
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

        // 5. Information Object Class & Field Reference (ITU-T X.681)
        .add_production("ObjectClassAssignment", {"TypeIdentifier", symassign, "CLASS", "{", "FieldList", "}"})
        .add_production("ObjectClassAssignment", {"TypeIdentifier", symassign, "CLASS", "{", "FieldList", "}", "WITH", "SYNTAX", "{", "SyntaxList", "}"})

        .add_production("FieldList", {"FieldList", ",", "Field"})
        .add_production("FieldList", {"Field"})
        .add_production("Field", {"&", "ComponentType"})
        .add_production("Field", {"&", "ComponentType", "UNIQUE"})
        .add_production("Field", {"&", symid})
        .add_production("Field", {"&", "TypeIdentifier"})

        .add_production("SyntaxList", {"SyntaxList", "SyntaxItem"})
        .add_production("SyntaxList", {"SyntaxItem"})
        .add_production("SyntaxItem", {"&", "TypeIdentifier"})
        .add_production("SyntaxItem", {"TypeIdentifier"})

        .add_production("ObjectClassFieldType", {"TypeIdentifier", "ClassFieldReference"})
        .add_production("ClassFieldReference", {".", "&", "TypeIdentifier"})
        .add_production("ClassFieldReference", {".", "&", symid})

        .add_production("InformationObjectAssignment", {symid, "TypeIdentifier", symassign, "{", "SettingList", "}"})
        .add_production("InformationObjectAssignment", {symid, symid, symassign, "{", "SettingList", "}"})
        .add_production("SettingList", {"SettingList", "SettingItem"})
        .add_production("SettingList", {"SettingItem"})

        .add_production("SettingItem", {"TypeIdentifier", "ValueElement"})
        .add_production("SettingItem", {"TypeIdentifier", "Type"})

        // Parameterized Value / Reference
        .add_production("ParameterizedValue", {symid, "{", "ActualParameterList", "}"})
        .add_production("ParameterizedValue", {"TypeIdentifier", "{", "ActualParameterList", "}"})

        .add_production("ValueElement", {"TypeIdentifier"})
        .add_production("ValueElement", {"ParameterizedValue"})
        .add_production("ValueElement", {symnum})
        .add_production("ValueElement", {symfp})
        .add_production("ValueElement", {symqs})
        .add_production("ValueElement", {symhexstr})
        .add_production("ValueElement", {"MIN"})
        .add_production("ValueElement", {"MAX"})
        .add_production("ValueElement", {"TRUE"})
        .add_production("ValueElement", {"FALSE"})

        // 6. Constraints & Subtype Specifications (ITU-T X.682)
        .add_production("Constraints", {"Constraints", "Constraint"})
        .add_production("Constraints", {"Constraint"})

        .add_production("Constraint", {"(", "ConstraintSpec", ")"})
        .add_production("ConstraintSpec", {"SubtypeElementSetSpec"})
        .add_production("ConstraintSpec", {"ALL EXCEPT", "SubtypeElementSetSpec"})

        .add_production("SubtypeElementSetSpec", {"SubtypeElementSetSpec", "UnionOperation", "SubtypeElement"})
        .add_production("SubtypeElementSetSpec", {"SubtypeElementSetSpec", "EXCEPT", "SubtypeElement"})
        .add_production("SubtypeElementSetSpec", {"SubtypeElementSetSpec", "IntersectOperation", "SubtypeElement"})
        .add_production("SubtypeElementSetSpec", {"SubtypeElementSetSpec", "SubtypeElement"})
        .add_production("SubtypeElementSetSpec", {"SubtypeElement"})

        .add_production("SubtypeElement", {"SubtypeElement", "IntersectOperation", "PrimaryElement"})
        .add_production("SubtypeElement", {"PrimaryElement"})

        .add_production("UnionOperation", {","})
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
        .add_production("PrimaryElement", {"(", "ConstraintSpec", ")"})
        .add_production("PrimaryElement", {"ObjectSetSpec"})
        .add_production("PrimaryElement", {"ObjectSetSpec", "RelationalConstraint"})

        .add_production("ObjectSetSpec", {"{", "TypeIdentifier", "}"})
        .add_production("RelationalConstraint", {"{", "@", symid, "}"})
        .add_production("SizeConstraint", {"SIZE", "Constraint"});

    // 7. Terminals Registration
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
        .add_terminal(symhexstr)

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

        .add_terminal(symid)
        .add_terminal(symid)
        .add_terminal(symid)

        .add_terminal("CLASS")
        .add_terminal("WITH")
        .add_terminal("SYNTAX")
        .add_terminal("UNIQUE")

        .add_terminal("$");

    parser.set_grammar(std::move(grammar));

    return parser.learn();
}

return_t asn1_advisor::import_glr_parser(glr_parser& parser) {
    binary_parsing_table bpt;
    return bpt.read("asn1.ptb", parser);
}

}  // namespace io
}  // namespace hotplace
