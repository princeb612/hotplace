/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_cfg_lalr1.cpp
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
#include <hotplace/sdk/io/parser/lalr1_parser.hpp>
#include <hotplace/sdk/io/parser/parser_resource.hpp>

namespace hotplace {
namespace io {

parser_t& asn1_advisor::get_notation_parser_by_build() {
    if (false == _lalr1_parser_by_build.ready()) {
        prepare_lalr1_notation_parser(_lalr1_parser_by_build);
    }
    return _lalr1_parser_by_build;
}

parser_t& asn1_advisor::get_notation_parser_by_import() {
    if (false == _lalr1_parser_by_import.ready()) {
        import_lalr1_notation_parser(_lalr1_parser_by_import);
    }
    return _lalr1_parser_by_import;
}

return_t asn1_advisor::prepare_lalr1_notation_parser(parser_t& parser) {
    auto resource = parser_resource::get_instance();
    auto symid = resource->nameof(token_identifier);     // "identifier"
    auto symnum = resource->nameof(token_number);        // symnum
    auto symfp = resource->nameof(token_floatingpoint);  // "floatingpoint"
    auto symqs = resource->nameof(token_quot_string);    // "quot_string"
    auto symuser = resource->nameof(token_usertype);     // "usertype"
    auto symassign = resource->nameof(token_assign);     // "::="
    auto symhexstr = resource->nameof(token_hexstring);  // "hex_string"

    cfg_grammar grammar;
    grammar
        // rule revision (.ptb file revision)
        .set_revision(2)
        // 1. Root & Entry Points (Supports Multiple Modules, Single Module, Standalone Statements)
        // Top level & Assignments
        .add_production("S'", {"Start"})
        .add_production("Start", {"Statement"})
        .add_production("Start", {"ComponentType"})
        .add_production("Start", {"Type"})
        .add_production("Start", {"TagSpec"})

        // 2. Module Definition & Exports/Imports (ITU-T X.680)
        // 3. Statements & Assignments (Standard & Parameterized)
        .add_production("Statement", {"Assignment"})

        .add_production("Assignment", {"TypeAssignment"})

        // Standard Type TypeAssignment
        .add_production("TypeAssignment", {"DefinedType", symassign, "Type"})
        .add_production("TypeAssignment", {"DefinedType", symassign, "Type", "Constraint"})

        .add_production("DefinedType", {symuser})

        // 4. Type Specifications & Extension Markers (Version 1 & 2)
        .add_production("Type", {"SimpleTypeSpec"})
        .add_production("Type", {"TaggedTypeSpec"})
        .add_production("Type", {"ReferencedTypeSpec"})
        .add_production("Type", {"EnumeratedType"})
        .add_production("Type", {"SequenceTypeSpec"})
        .add_production("Type", {"SequenceOfTypeSpec"})
        .add_production("Type", {"SetTypeSpec"})
        .add_production("Type", {"SetOfTypeSpec"})
        .add_production("Type", {"ChoiceTypeSpec"})

        // Referenced Types
        .add_production("TypeIdentifier", {symuser})
        .add_production("TypeIdentifier", {symid})

        .add_production("ReferencedTypeSpec", {"TypeIdentifier"})

        .add_production("NamedType", {symid, "Type"})

        .add_production("ComponentType", {"NamedType"})
        .add_production("ComponentType", {"NamedType", "Constraints"})
        .add_production("ComponentType", {"NamedType", "OptionalitySpec"})
        .add_production("ComponentType", {"NamedType", "Constraints", "OptionalitySpec"})

        // ComponentTypeList rules for SEQUENCE / SET / CHOICE
        .add_production("ComponentTypeList", {"ComponentTypeList", ",", "ComponentType"})
        .add_production("ComponentTypeList", {"ComponentType"})

        .add_production("ComponentTypeLists", {"Constraint", "{", "ComponentTypeList", "}"})
        .add_production("ComponentTypeLists", {"{", "ComponentTypeList", "}"})
        .add_production("ComponentTypeLists", {"Constraint", "{", "}"})
        .add_production("ComponentTypeLists", {"{", "}"})

        // Constructed Types (SEQUENCE, SET, CHOICE)
        .add_production("SequenceTypeSpec", {"SEQUENCE", "ComponentTypeLists"})
        .add_production("SetTypeSpec", {"SET", "ComponentTypeLists"})
        .add_production("ChoiceTypeSpec", {"CHOICE", "ComponentTypeLists"})

        // SEQUENCE OF
        .add_production("SequenceOfTypeSpec", {"SEQUENCE", "SizeConstraint", "OF", "Type"})
        .add_production("SequenceOfTypeSpec", {"SEQUENCE", "Constraint", "OF", "Type"})
        .add_production("SequenceOfTypeSpec", {"SEQUENCE", "OF", "Type"})

        // SET OF
        .add_production("SetOfTypeSpec", {"SET", "SizeConstraint", "OF", "Type"})
        .add_production("SetOfTypeSpec", {"SET", "Constraint", "OF", "Type"})
        .add_production("SetOfTypeSpec", {"SET", "OF", "Type"})

        .add_production("OptionalitySpec", {"OPTIONAL"})
        .add_production("OptionalitySpec", {"DEFAULT", "ValueElement"})
        .add_production("OptionalitySpec", {"DEFAULT", "{", "}"})

        // Tagged Type Specifications
        // TaggedType ::= Tag Type | Tag IMPLICIT Type | Tag EXPLICIT Type
        .add_production("TaggedTypeSpec", {"TagSpec", "IMPLICIT", "Type"})
        .add_production("TaggedTypeSpec", {"TagSpec", "EXPLICIT", "Type"})
        .add_production("TaggedTypeSpec", {"TagSpec", "Type"})

        // Tag ::= "[" Class ClassNumber "]"
        .add_production("TagSpec", {"[", "UNIVERSAL", symnum, "]"})
        .add_production("TagSpec", {"[", "APPLICATION", symnum, "]"})
        .add_production("TagSpec", {"[", "PRIVATE", symnum, "]"})
        .add_production("TagSpec", {"[", symnum, "]"})

        // Enum Specifications
        .add_production("EnumeratedType", {"ENUMERATED", "{", "Enumerations", "}"})

        // ENUMERATED
        .add_production("Enumerations", {"Enumerations", ",", "Enumeration"})
        .add_production("Enumerations", {"Enumeration"})
        // INTEGER { a(1), b(2) }
        .add_production("Enumeration", {symid, "(", symnum, ")"})
        // ENUMERATED { red, green, blue }
        .add_production("Enumeration", {symid})

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
        .add_production("ValueElement", {symnum})
        .add_production("ValueElement", {symfp})
        .add_production("ValueElement", {symqs})
        .add_production("ValueElement", {symhexstr})
        .add_production("ValueElement", {"MIN"})
        .add_production("ValueElement", {"MAX"})
        .add_production("ValueElement", {"TRUE"})
        .add_production("ValueElement", {"FALSE"})

        // 6. Constraints & Subtype Specifications (ITU-T X.682 - Ambiguity Fixed)
        .add_production("Constraints", {"Constraints", "Constraint"})
        .add_production("Constraints", {"Constraint"})

        .add_production("Constraint", {"(", "ConstraintSpec", ")"})

        .add_production("ConstraintSpec", {"SubtypeElementSetSpec"})
        .add_production("ConstraintSpec", {"ALL EXCEPT", "SubtypeElementSetSpec"})  // lexer supports single token (token_allexcept)

        .add_production("SubtypeElementSetSpec", {"SubtypeElementSetSpec", "UnionOperation", "SubtypeElement"})
        .add_production("SubtypeElementSetSpec", {"SubtypeElementSetSpec", "EXCEPT", "SubtypeElement"})
        .add_production("SubtypeElementSetSpec", {"SubtypeElementSetSpec", "SubtypeElement"})
        .add_production("SubtypeElementSetSpec", {"SubtypeElement"})

        .add_production("SubtypeElement", {"SubtypeElement", "IntersectOperation", "PrimaryElement"})
        .add_production("SubtypeElement", {"PrimaryElement"})

        .add_production("UnionOperation", {","})  // MultiSize ::= OCTET STRING (SIZE (1..10, 20..30))
        .add_production("UnionOperation", {"|"})
        .add_production("UnionOperation", {"UNION"})
        .add_production("IntersectOperation", {"^"})
        .add_production("IntersectOperation", {"INTERSECTION"})
        .add_production("IntersectOperation", {"INTERSECT"})

        .add_production("PrimaryElement", {"ValueElement"})
        .add_production("PrimaryElement", {"ValueElement", "..", "ValueElement"})            // [from, to]
        .add_production("PrimaryElement", {"ValueElement", "..", "<", "ValueElement"})       // [from, to)
        .add_production("PrimaryElement", {"ValueElement", "<", "..", "ValueElement"})       // (from, to]
        .add_production("PrimaryElement", {"ValueElement", "<", "..", "<", "ValueElement"})  // (from, to)
        .add_production("PrimaryElement", {"SIZE", "Constraint"})
        .add_production("PrimaryElement", {"FROM", "Constraint"})
        .add_production("PrimaryElement", {"PATTERN", symqs})
        .add_production("PrimaryElement", {"(", "ConstraintSpec", ")"})

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

        .add_terminal("$");

    parser.set_grammar(std::move(grammar));

    return parser.learn();
}

return_t asn1_advisor::import_lalr1_notation_parser(lalr1_parser& parser) {
    binary_parsing_table bpt;
    return bpt.read("asn1notation.ptb", parser);
}

}  // namespace io
}  // namespace hotplace
