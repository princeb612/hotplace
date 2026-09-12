/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_parser.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * see README.md
 */

#include <hotplace/sdk/base/stream/basic_stream.hpp>
#include <hotplace/sdk/base/system/trace.hpp>
#include <hotplace/sdk/io/asn.1/basic/asn1_resource.hpp>
#include <hotplace/sdk/io/asn.1/runtime/asn1_parser.hpp>
#include <hotplace/sdk/io/parser/parser_resource.hpp>

namespace hotplace {
namespace io {

bool asn1_parser::prepare() {
    auto& lex = get_lex();
    // handle_quoted to 1
    lex.get_config().set("handle_comments", 1).set("handle_quoted", 1).set("handle_token", 1).set("handle_lvalue_usertype", 1);
    lex.prepare();

    // ASN.1 tokens
    auto asn1resource = asn1_resource::get_instance();
    asn1resource->for_each(resource_type_t::token_type_asn1, [&lex](uint32 token, const std::string& name) -> void { lex.add_token(name, token); });

    /**
     *                 source
     *                   │
     *                   ▼
     *              lexical pass
     *                   │
     *           ┌───────┴───────┐
     *           │               │
     *        tokens           lvalues
     *                           │
     *                           ▼
     *                     rlookup names
     *                           │
     *                           ▼
     *                   token_usertype
     *                           │
     *                           ▼
     *                 token reclassification
     *                           │
     *                           ▼
     *                         LALR
     */

    // get several CFG symbols from the lexical analyzer.

    auto resource = parser_resource::get_instance();
    auto symid = resource->nameof(token_identifier);     // "identifier"
    auto symnum = resource->nameof(token_number);        // "number"
    auto symfp = resource->nameof(token_floatingpoint);  // "floatingpoint"
    auto symqs = resource->nameof(token_quot_string);    // "quot_string"
    auto symuser = resource->nameof(token_usertype);     // "usertype"

    // CFG - production, terminal, non-terminal, start symbol
    cfg_grammar grammar;
    grammar
        // Top level & Assignments
        .add_production("S'", {"Statement"})
        .add_production("Statement", {"Assignment"})
        .add_production("Statement", {"TypeSpec"})
        .add_production("Statement", {"Constraint"})
        .add_production("Statement", {"Field"})
        .add_production("Statement", {"TagPrefix"})

        // Assignment: LHS (asn1_referenced_type::define 시점)
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
        .add_production("StatementSetOf", {"SET", "SizeConstraint", "OF", "TypeSpec"})
        .add_production("StatementSetOf", {"SET", "Constraint", "OF", "TypeSpec"})
        .add_production("StatementSetOf", {"SET", "OF", "TypeSpec"})
        .add_production("SizeConstraint", {"SIZE", "Constraint"})
        .add_production("StatementSet", {"SET", "Constraint", "{", "FieldList", "}"})
        .add_production("StatementSet", {"SET", "{", "FieldList", "}"})
        .add_production("StatementSet", {"SET", "Constraint", "{", "}"})
        .add_production("StatementSet", {"SET", "{", "}"})
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
        .add_production("FieldOpt", {"DEFAULT", symid})
        .add_production("FieldOpt", {"DEFAULT", symuser})
        .add_production("FieldOpt", {"DEFAULT", symnum})
        .add_production("FieldOpt", {"DEFAULT", "{", "}"})

        // Type Spec Definition
        .add_production("TypeSpec", {"TypeBase"})
        .add_production("TypeSpec", {"EnumType"})
        .add_production("TypeSpec", {"StatementSequence"})
        .add_production("TypeSpec", {"StatementSequenceOf"})
        .add_production("TypeSpec", {"StatementSet"})
        .add_production("TypeSpec", {"StatementSetOf"})
        .add_production("TypeSpec", {"StatementChoice"})

        // RHS referenced type symbol (asn1_referenced_type::refer 시점)
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

        // Constraints Grammar
        .add_production("Constraint", {"(", "ConstraintExpr", ")"})
        .add_production("ConstraintExpr", {"SubtypeElementSet"})
        .add_production("ConstraintExpr", {"ALL", "EXCEPT", "SubtypeElementSet"})
        .add_production("ConstraintExpr", {"ALL EXCEPT", "SubtypeElementSet"})
        // Union Level
        .add_production("SubtypeElementSet", {"SubtypeElementSet", "|", "SubtypeElement"})
        .add_production("SubtypeElementSet", {"SubtypeElementSet", ",", "SubtypeElement"})
        .add_production("SubtypeElementSet", {"SubtypeElementSet", "UNION", "SubtypeElement"})
        .add_production("SubtypeElementSet", {"SubtypeElementSet", "EXCEPT", "SubtypeElement"})
        .add_production("SubtypeElementSet", {"SubtypeElement"})
        // Intersection Level
        .add_production("SubtypeElement", {"SubtypeElement", "^", "PrimaryElement"})
        .add_production("SubtypeElement", {"SubtypeElement", "INTERSECTION", "PrimaryElement"})
        .add_production("SubtypeElement", {"PrimaryElement"})
        // Primary Elements
        .add_production("PrimaryElement", {"ValueElement"})
        .add_production("PrimaryElement", {"ValueElement", "..", "ValueElement"})
        .add_production("PrimaryElement", {"ValueElement", "..", "<", "ValueElement"})  // exclusive range support
        .add_production("PrimaryElement", {"SIZE", "Constraint"})
        .add_production("PrimaryElement", {"FROM", "Constraint"})
        .add_production("PrimaryElement", {"PATTERN", symqs})
        .add_production("PrimaryElement", {"(", "ConstraintExpr", ")"})
        // Value Elements
        .add_production("ValueElement", {symid})
        .add_production("ValueElement", {symuser})
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

    get_lalr().set_grammar(std::move(grammar));

    return get_lalr().build_table();
}

}  // namespace io
}  // namespace hotplace
