/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_cfg_parameterized.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include "asn1_cfg_parameterized.hpp"

return_t prepare_glr_parser_asn1_parameterized(parser_t& parser);

parser_t& get_glr_parser_asn1_paramerized_by_build() {
    static glr_parser parser;
    static const return_t ready = prepare_glr_parser_asn1_parameterized(parser);
    (void)ready;
    return parser;
}

return_t prepare_glr_parser_asn1_parameterized(parser_t& parser) {
    return_t ret = errorcode_t::success;

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
    auto symassign = resource->nameof(token_assign);                // "::="

    cfg_grammar grammar;
    // 1. Root & Entry Points (Supports Multiple Modules, Single Module, Standalone Statements)
    grammar
        // Top level Entry Point
        .add_production("S'", {"Statement"})

        // 2. Module Definition & Exports/Imports (ITU-T X.680)
        // 3. Statements & Assignments (Standard & Parameterized)
        .add_production("Statement", {"Assignment"})
        .add_production("Statement", {"Type"})
        .add_production("Statement", {"ComponentType"})
        .add_production("Statement", {"TagSpec"})

        .add_production("Assignment", {"TypeAssignment"})
        // Standard Type TypeAssignment
        .add_production("TypeAssignment", {"DefinedType", symassign, "Type"})
        .add_production("TypeAssignment", {"DefinedType", symassign, "Type", "Constraint"})

        // Parameterized TypeAssignment (ITU-T X.683)
        .add_production("TypeAssignment", {symuserparamtype, "{", "ParameterList", "}", symassign, "Type"})
        .add_production("TypeAssignment", {symuserparamtype, "{", "ParameterList", "}", symassign, "Type", "Constraint"})

        .add_production("DefinedType", {symuser})
        .add_production("DefinedType", {symuserparamtype})

        .add_production("ParameterList", {"ParameterList", ",", "Parameter"})
        .add_production("ParameterList", {"Parameter"})
        .add_production("Parameter", {symparamtype, ":", symparamvalue})
        .add_production("Parameter", {symparamtype, ":", symuser})
        .add_production("Parameter", {symparamtype})
        .add_production("Parameter", {"Type", ":", symparamvalue})

        // 4. Type Specifications & Extension Markers (Version 1 & 2)
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

        .add_production("TypeIdentifier", {symuser})
        .add_production("TypeIdentifier", {symid})

        .add_production("ReferencedTypeSpec", {"TypeIdentifier"})
        .add_production("ReferencedTypeSpec", {symparamtype})
        .add_production("ReferencedTypeSpec", {symuserparamtype})
        .add_production("ReferencedTypeSpec", {symuserparamtype, "{", "ActualParameterList", "}"})
        .add_production("ReferencedTypeSpec", {symparamtype, "{", "ActualParameterList", "}"})
        .add_production("ReferencedTypeSpec", {symid, "{", "ActualParameterList", "}"})

        .add_production("NamedType", {symid, "Type"})

        .add_production("ComponentType", {"NamedType"})
        .add_production("ComponentType", {"NamedType", "Constraint"})
        .add_production("ComponentType", {"NamedType", "OptionalitySpec"})
        .add_production("ComponentType", {"NamedType", "Constraint", "OptionalitySpec"})

        .add_production("ComponentTypeList", {"ComponentTypeList", ",", "ComponentType"})
        .add_production("ComponentTypeList", {"ComponentType"})

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

        .add_production("FieldList", {"FieldList", ",", "ComponentType"})
        .add_production("FieldList", {"ComponentType"})

        .add_production("OptionalitySpec", {"OPTIONAL"})
        .add_production("OptionalitySpec", {"DEFAULT", "ValueElement"})
        .add_production("OptionalitySpec", {"DEFAULT", "{", "}"})

        .add_production("ActualParameterList", {"ActualParameterList", ",", "ActualParameter"})
        .add_production("ActualParameterList", {"ActualParameter"})
        .add_production("ActualParameter", {"Type"})
        .add_production("ActualParameter", {symparamvalue})
        .add_production("ActualParameter", {symparamtype})
        .add_production("ActualParameter", {symnum})
        .add_production("ActualParameter", {symfp})
        .add_production("ActualParameter", {symqs})
        .add_production("ActualParameter", {"TRUE"})
        .add_production("ActualParameter", {"FALSE"})

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

        // Enum Specifications & Extensions
        .add_production("EnumeratedType", {"ENUMERATED", "{", "Enumerations", "ExtensionAdditionEnumeration", "}"})
        .add_production("EnumeratedType", {"ENUMERATED", "{", "Enumerations", "}"})
        // ENUMERATED
        .add_production("Enumerations", {"Enumerations", ",", "Enumeration"})
        .add_production("Enumerations", {"Enumeration"})
        // INTEGER { a(1), b(2) }
        .add_production("Enumeration", {symid, "(", symnum, ")"})
        // ENUMERATED { red, green, blue }
        .add_production("Enumeration", {symid})

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

        .add_production("ValueElement", {symparamvalue})
        .add_production("ValueElement", {symnum})
        .add_production("ValueElement", {symfp})
        .add_production("ValueElement", {symqs})
        .add_production("ValueElement", {"MIN"})
        .add_production("ValueElement", {"MAX"})
        .add_production("ValueElement", {"TRUE"})
        .add_production("ValueElement", {"FALSE"})

        // 5. Information Object Class & Field Reference (ITU-T X.681)
        // 6. Constraints & Subtype Specifications (ITU-T X.682 - Ambiguity Fixed)
        .add_production("Constraint", {"(", "ConstraintSpec", ")"})

        .add_production("ConstraintSpec", {"SubtypeElementSetSpec"})
        .add_production("ConstraintSpec", {"ALL EXCEPT", "SubtypeElementSetSpec"})

        .add_production("SubtypeElementSetSpec", {"SubtypeElementSetSpec", "UnionOperation", "SubtypeElement"})
        .add_production("SubtypeElementSetSpec", {"SubtypeElementSetSpec", "EXCEPT", "SubtypeElement"})
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

        .add_production("SizeConstraint", {"SIZE", "Constraint"});

    // 7. Terminals Registration
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
    _test_case.test(ret, __FUNCTION__, "GLR parser - ASN.1 for Parameterized (build parsing table)");
    return ret;
}
