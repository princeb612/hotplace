/* vim: set tabstop=4 parser_action_t::shiftwidth=4 softtabstop=4 expandtab smarttab : */
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

#include <hotplace/sdk/io/asn.1/asn1_resource.hpp>
#include <hotplace/sdk/io/parser/lalr1_parser.hpp>
#include <hotplace/sdk/io/parser/parser_resource.hpp>

namespace hotplace {
namespace io {

return_t prepare_lalr1_parser_asn1notation(parser_t& parser);
return_t import_lalr1_parser_asn1notation(lalr1_parser& parser);

parser_t& get_lalr1_parser_asn1_notation_by_build() {
    static lalr1_parser parser;
    static const return_t ready = prepare_lalr1_parser_asn1notation(parser);
    (void)ready;
    return parser;
}

parser_t& get_lalr1_parser_asn1_notation_by_import() {
    static lalr1_parser parser;
    static const return_t ready = import_lalr1_parser_asn1notation(parser);
    (void)ready;
    return parser;
}

return_t import_lalr1_parser_asn1notation(lalr1_parser& parser) { return parser.import(asn1_notation_productions, asn1_notation_action_table, asn1_notation_goto_table); }

return_t prepare_lalr1_parser_asn1notation(parser_t& parser) {
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

        .add_production("TypeSpec", {"SimpleTypeSpec"})
        .add_production("TypeSpec", {"TaggedTypeSpec"})
        .add_production("TypeSpec", {"ReferencedTypeSpec"})
        .add_production("TypeSpec", {"EnumTypeSpec"})
        .add_production("TypeSpec", {"SequenceTypeSpec"})
        .add_production("TypeSpec", {"SequenceOfTypeSpec"})
        .add_production("TypeSpec", {"SetTypeSpec"})
        .add_production("TypeSpec", {"SetOfTypeSpec"})
        .add_production("TypeSpec", {"ChoiceTypeSpec"})

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
        .add_production("ChoiceTypeSpec", {"CHOICE", "Constraint", "{", "FieldList", "}"})
        .add_production("ChoiceTypeSpec", {"CHOICE", "{", "FieldList", "}"})
        .add_production("ChoiceTypeSpec", {"CHOICE", "Constraint", "{", "}"})
        .add_production("ChoiceTypeSpec", {"CHOICE", "{", "}"})

        .add_production("NamedTypeSpec", {symid, "TypeSpec"})

        .add_production("FieldList", {"FieldList", ",", "Field"})
        .add_production("FieldList", {"Field"})
        .add_production("Field", {"NamedTypeSpec"})
        .add_production("Field", {"NamedTypeSpec", "Constraint"})
        .add_production("Field", {"NamedTypeSpec", "FieldSpecifier"})
        .add_production("Field", {"NamedTypeSpec", "Constraint", "FieldSpecifier"})
        .add_production("FieldSpecifier", {"OPTIONAL"})
        .add_production("FieldSpecifier", {"DEFAULT", symnum})
        .add_production("FieldSpecifier", {"DEFAULT", symqs})
        .add_production("FieldSpecifier", {"DEFAULT", "{", "}"})

        .add_production("Identifier", {symuser})
        .add_production("Identifier", {symid})
        .add_production("ReferencedTypeSpec", {"Identifier"})

        .add_production("TaggedTypeSpec", {"TagPrefix", "TagSpec", "TypeSpec"})
        .add_production("TaggedTypeSpec", {"TagPrefix", "TypeSpec"})

        .add_production("TagPrefix", {"[", "TagClass", symnum, "]"})
        .add_production("TagPrefix", {"[", symnum, "]"})

        .add_production("TagClass", {"UNIVERSAL"})
        .add_production("TagClass", {"APPLICATION"})
        .add_production("TagClass", {"PRIVATE"})
        .add_production("TagSpec", {"IMPLICIT"})
        .add_production("TagSpec", {"EXPLICIT"})

        .add_production("EnumTypeSpec", {"ENUMERATED", "{", "EnumList", "}"})
        .add_production("EnumList", {"EnumList", ",", "EnumItem"})
        .add_production("EnumList", {"EnumItem"})
        .add_production("EnumItem", {symid, "(", symnum, ")"})

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

        .add_production("Constraint", {"(", "ConstraintExpr", ")"})

        .add_production("ConstraintExpr", {"SubtypeElementSet"})
        .add_production("ConstraintExpr", {"ALL EXCEPT", "SubtypeElementSet"})  // lexer supports single token (token_allexcept)

        .add_production("SubtypeElementSet", {"SubtypeElementSet", "UnionOperation", "SubtypeElement"})
        .add_production("SubtypeElementSet", {"SubtypeElementSet", "EXCEPT", "SubtypeElement"})
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
        .add_terminal("DATE-DATE")
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
        .add_terminal("|")
        .add_terminal("^")
        .add_terminal("INTERSECTION")
        .add_terminal("INTERSECT")
        .add_terminal("EXCEPT")
        .add_terminal("ALL EXCEPT")
        .add_terminal("ALL")
        .add_terminal("SIZE")
        .add_terminal("FROM")
        .add_terminal("PATTERN")
        .add_terminal("MIN")
        .add_terminal("MAX")
        .add_terminal(symid)
        .add_terminal(symuser)
        .add_terminal(symnum)
        .add_terminal(symfp)
        .add_terminal(symqs)
        .add_terminal("$");

    parser.set_grammar(std::move(grammar));

    // _logger->writeln("building LALR(1) parsing table dynamically...");

    return parser.learn();
    // _logger->writeln("LALR table generation %s", (errorcode_t::success == ret) ? "success" : "failure");
    // _test_case.test(ret, __FUNCTION__, "LALR(1) parser - ASSN.1 for Notation (build parsing table)");
}

}  // namespace io
}  // namespace hotplace
