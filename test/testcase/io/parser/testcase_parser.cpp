/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   testcase_parser.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 */

#include <hotplace/test/testcase/io/sample.hpp>

static void prepare_asn1_tokens(lexical_analyzer& lex) {
    // handle_quoted to 1
    lex.get_config().set("handle_comments", 1).set("handle_quoted", 1).set("handle_token", 1);
    // ASN.1 tokens
    auto resource = asn1_resource::get_instance();
    resource->for_each(resource_type_t::token_type_asn1, [&lex](uint32 token, const std::string& name) -> void { lex.add_token(name, token); });
}

void test_options() {
    _test_case.begin("lexical analyzer");
    struct testvector {
        const char* notation;
        size_t tokens;
        uint32 first;
        int16 handle_comments;
        int16 handle_lvalue_usertype;
    } table[] = {
        {R"(Type ::= VisibleString ("A" | "B" | "C" | "D"))", 12, token_lvalue, 0, 0},             //
        {"Type ::= SEQUENCE {} -- empty SEQUENCE", 8, token_lvalue, 0},                            // "--" as comments, cf. prepare_asn1_tokens
        {"Type ::= SEQUENCE {} -- empty SEQUENCE", 6, token_lvalue, 1},                            // "-- empty SEQUENCE" as comments
        {"Type1 ::= SEQUENCE {name VisibleString, ok BOOLEAN} -- SEQUENCE", 12, token_lvalue, 0},  //
        {"Type1 ::= SEQUENCE {name VisibleString, ok BOOLEAN} -- SEQUENCE", 11, token_lvalue, 1},  // "-- SEQUENCE" as comments
        {"Type ::= SEQUENCE {} -- empty SEQUENCE", 6, token_usertype, 1, 1},                       // Type (usertype not lvalue)
        {"Name ::= VisibleString", 3, token_usertype, 1, 1},                                       // Name (usertype not lvalue)
        {"Type1 ::= SEQUENCE {name Name, ok BOOLEAN} -- SEQUENCE", 11, token_usertype, 1, 1},      // Type1, Name (usertype)
        {"Name2 ::= [APPLICATION 1] IMPLICIT SEQUENCE { givenName VisibleString, initial VisibleString, familyName VisibleString}", 18, token_usertype, 1, 1},
        {R"(Type ::= INTEGER (1..10 | 20..30))", 12, token_lvalue, 0, 0},
    };

    lexical_analyzer lex;
    lexical_context context;  // shares context to test previously defined usertype

    lex.prepare();
    prepare_asn1_tokens(lex);

    for (const auto& entry : table) {
        _logger->colorln(entry.notation);

        lex.get_config().set("handle_comments", entry.handle_comments).set("handle_lvalue_usertype", entry.handle_lvalue_usertype);
        auto test = lex.parse(context, entry.notation, strlen(entry.notation));

        uint32 cnt = 0;
        uint32 first = token_unknown;
        auto dump_handler = [&lex, &cnt, &first](const token_description* desc) -> bool {
            if (0 == cnt) first = desc->type;
            _logger->writeln("[%03u] line %zi type %d(%s) index %d pos %zi len %zi (%.*s)", cnt++, desc->line, desc->type, lex.nameof_token(desc->type).c_str(),
                             desc->index, desc->pos, desc->size, (unsigned)desc->size, desc->p);
            return true;
        };
        context.for_each(dump_handler);
        _test_case.test(test, __FUNCTION__, "parse usertype");
        _test_case.assert(entry.tokens == cnt, __FUNCTION__, "handle_comments %i handle_lvalue_usertype %i", entry.handle_comments, entry.handle_lvalue_usertype);
        _test_case.assert(entry.first == first, __FUNCTION__, "first token type %s", lex.nameof_token(first).c_str());
    }
}

void test_lexical() {
    _test_case.begin("lexical analyzer");

    constexpr char asn1_structure[] =
        R"(PersonnelRecord ::= [APPLICATION 0] IMPLICIT SET {
                name Name,
                title [0] VisibleString,
                number EmployeeNumber,
                dateOfHire [1] Date,
                nameOfSpouse [2] Name,
                children [3] IMPLICIT SEQUENCE OF ChildInformation DEFAULT {} }
            ChildInformation ::= SET { name Name, dateOfBirth [0] Date}
            Name ::= [APPLICATION 1] IMPLICIT SEQUENCE { givenName VisibleString, initial VisibleString, familyName VisibleString}
            EmployeeNumber ::= [APPLICATION 2] IMPLICIT INTEGER
            Date ::= [APPLICATION 3] IMPLICIT VisibleString -- YYYYMMDD)";

    lexical_analyzer lex;
    lexical_context context;

    lex.prepare();

    _logger->colorln("basic tokens + handle_lvalue_usertype 0");
    lex.parse(context, asn1_structure, strlen(asn1_structure));
    uint32 cnt = 0;

    auto dump_handler = [&lex, &cnt](const token_description* desc) -> bool {
        _logger->writeln("[%03u] line %zi type %d(%s) index %d pos %zi len %zi (%.*s)", cnt++, desc->line, desc->type, lex.nameof_token(desc->type).c_str(), desc->index,
                         desc->pos, desc->size, (unsigned)desc->size, desc->p);
        return true;
    };

    context.for_each(dump_handler);
    _test_case.assert(105 == cnt, __FUNCTION__, "tokenize");

    // load ASN.1 tokens
    _logger->colorln("ASN.1 tokens + handle_lvalue_usertype 1");
    prepare_asn1_tokens(lex);
    lex.get_config().set("handle_lvalue_usertype", 1);

    lex.add_token("::=", token_assign).add_token("--", token_comments);
    lex.parse(context, asn1_structure, strlen(asn1_structure));
    cnt = 0;
    context.for_each(dump_handler);
    _test_case.assert(93 == cnt, __FUNCTION__, "tokenize");
}

void test_lalr() {
    _test_case.begin("LALR parser");

    lexical_analyzer lex;
    cfg_grammar g;
    lalr_parser lalr;
    return_t ret = errorcode_t::success;
    bool result = true;

    __try2 {
        lex.prepare();
        prepare_asn1_tokens(lex);
        lex.get_config().set("handle_lvalue_usertype", 1);

        auto resource = parser_resource::get_instance();
        auto symid = resource->nameof(token_identifier);     // "identifier"
        auto symnum = resource->nameof(token_number);        // "number"
        auto symfp = resource->nameof(token_floatingpoint);  // "floatingpoint"
        auto symqs = resource->nameof(token_quot_string);    // "quot_string"
        auto symuser = resource->nameof(token_usertype);     // "usertype"

        g
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
            .add_production("ConstraintExpr", {"ALL EXCEPT", "SubtypeElementSet"})
            .add_production("ConstraintExpr", {"ALL", "EXCEPT", "SubtypeElementSet"})
            .add_production("SubtypeElementSet", {"SubtypeElementSet", "|", "IntersectionElement"})
            .add_production("SubtypeElementSet", {"SubtypeElementSet", ",", "IntersectionElement"})
            .add_production("SubtypeElementSet", {"SubtypeElementSet", "EXCEPT", "IntersectionElement"})
            .add_production("SubtypeElementSet", {"IntersectionElement"})
            .add_production("IntersectionElement", {"IntersectionElement", "INTERSECTION", "PrimaryElement"})
            .add_production("IntersectionElement", {"PrimaryElement"})
            .add_production("PrimaryElement", {"ValueElement"})
            .add_production("PrimaryElement", {"ValueElement", "..", "ValueElement"})
            .add_production("PrimaryElement", {"SIZE", "Constraint"})
            .add_production("PrimaryElement", {"FROM", "Constraint"})
            .add_production("PrimaryElement", {"PATTERN", symqs})
            .add_production("PrimaryElement", {"(", "ConstraintExpr", ")"})
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
        g.add_terminal("::=")
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

        lalr.set_grammar(std::move(g));

        _logger->writeln("building LALR(1) parsing table dynamically...");

        ret = lalr.build_table();
        _logger->writeln("LALR table generation %s", (errorcode_t::success == ret) ? "success" : "failure");
        _test_case.test(ret, __FUNCTION__, "build parsing table");

        if (false == result) {
            __leave2;
        }

        struct testvector {
            const char* notation;
        };

        // [NOTE] LHS is always camelcase no lowercase (cf. usertype)
        testvector table[] = {
            // Assignment
            {R"(Type1 ::= VisibleString)"},
            {R"(Type2 ::= [APPLICATION 3] IMPLICIT Type1)"},
            {R"(Type3 ::= [2] EXPLICIT Type2)"},
            {R"(Type1 ::= REAL)"},
            {R"(Product ::= SEQUENCE {id VisibleString})"},
            {R"(Location ::= INTEGER {homeOffice(0), fieldOffice(1), roving(2)})"},
            {R"(Flags ::= BIT STRING {read(0), write(1), execute(2)})"},
            {R"(Flags ::= BIT STRING)"},
            {R"(Data ::= OCTET STRING)"},
            {R"(Oid ::= OBJECT IDENTIFIER)"},
            {R"(RelOid ::= RELATIVE-OID)"},
            {R"(Time ::= UTCTime)"},
            {R"(Time ::= GeneralizedTime)"},
            {R"(Color ::= ENUMERATED {red(0), green(1), blue(2)})"},
            {R"(Type ::= SEQUENCE {})"},
            {R"(Type1 ::= SEQUENCE {name VisibleString, ok BOOLEAN})"},
            {R"(Person2 ::= SEQUENCE {name [0] IMPLICIT VisibleString})"},
            {R"(Person3 ::= SEQUENCE {name VisibleString, age INTEGER DEFAULT 20})"},
            {R"(Outer1 ::= SEQUENCE {inner SEQUENCE {name VisibleString}})"},
            {R"(Outer2 ::= SEQUENCE {inner [0] EXPLICIT SEQUENCE {name VisibleString}})"},
            {R"(Outer ::= SEQUENCE {inner SEQUENCE {child SEQUENCE {name VisibleString}}})"},
            {R"(Numbers ::= SEQUENCE OF INTEGER)"},
            {R"(Type1 ::= SET {z BOOLEAN, a INTEGER})"},
            {R"(Value ::= CHOICE {i INTEGER, s VisibleString})"},
            {R"(Value2 ::= CHOICE {i [0] IMPLICIT INTEGER, s [1] IMPLICIT VisibleString})"},
            {R"(Value3 ::= [0] EXPLICIT CHOICE {i INTEGER, s VisibleString})"},
            {R"(Person ::= SEQUENCE {id CHOICE {num INTEGER, name VisibleString}})"},
            {R"(Test ::= SEQUENCE {id INTEGER, data ANY})"},
            {R"(OptTest ::= SEQUENCE {name VisibleString, title [0] VisibleString OPTIONAL})"},
            // Constraints
            {R"(Type ::= INTEGER (1))"},
            {R"(Type ::= INTEGER (1 | 2))"},
            {R"(Type ::= INTEGER (1 | 2 | 3 | 6))"},
            {R"(Type ::= VisibleString ("A" | "B" | "C" | "D"))"},
            {R"(Type ::= INTEGER (1..10 | 20..30))"},
            {R"(Type ::= INTEGER ((1..100) INTERSECTION (50..200)))"},
            {R"(Type ::= INTEGER (1..100 EXCEPT 50))"},
            {R"(Type ::= INTEGER ((1..10 | 20..30) EXCEPT (5 | 25)))"},
            {R"(Temperature ::= REAL (0.0..100.0))"},
            {R"(Positive ::= REAL (0.0..MAX))"},
            {R"(Negative ::= REAL (MIN..0.0))"},
            {R"(Type ::= REAL (0.0..100.0 EXCEPT 50.0))"},
            {R"(Name ::= IA5String (SIZE(1)))"},
            {R"(Name ::= IA5String (SIZE(1 | 2 | 5)))"},
            {R"(Name ::= IA5String (SIZE(1..20)))"},
            {R"(Type ::= INTEGER (1..50 EXCEPT 20..30))"},
            {R"(Type ::= INTEGER (ALL EXCEPT 1..10))"},
            {R"(Type ::= INTEGER (0..255))"},
            {R"(Type ::= OCTET STRING (SIZE(16)))"},
            {R"(Name ::= IA5String (FROM ("ABC")))"},
            {R"(Numbers ::= SEQUENCE SIZE(1..4) OF INTEGER)"},
            {R"(Flags ::= BIT STRING (SIZE(8)))"},
            {R"(Person ::= SEQUENCE {age INTEGER (0..120), name UTF8String (SIZE(1..20))})"},
            {R"(ShortString ::= IA5String (SIZE (1..10)))"},
            {R"(ExactBuffer ::= OCTET STRING (SIZE (16)))"},
            {R"(RestrictedInt ::= INTEGER (1..100))"},
            {R"(LimitedInt ::= INTEGER (MIN..1000))"},
            {R"(MultiSize ::= OCTET STRING (SIZE (1..10, 20..30)))"},
            {R"(PhoneNumber ::= UTF8String (PATTERN "[0-9]{3}-[0-9]{4}-[0-9]{4}"))"},
            // clang-format off
            {R"(PersonnelRecord ::= [APPLICATION 0] IMPLICIT SET {name Name, title [0] VisibleString, number EmployeeNumber, dateOfHire [1] Date, nameOfSpouse [2] Name, children [3] IMPLICIT SEQUENCE OF ChildInformation DEFAULT {}})"},
            // clang-format on
            {R"(ChildInformation ::= SET { name Name, dateOfBirth [0] Date})"},
            {R"(Name ::= [APPLICATION 1] IMPLICIT SEQUENCE { givenName VisibleString, initial VisibleString, familyName VisibleString})"},
            {R"(EmployeeNumber ::= [APPLICATION 2] IMPLICIT INTEGER)"},
            {R"(Date ::= [APPLICATION 3] IMPLICIT VisibleString -- YYYYMMDD)"},
            // non-assignment
            {R"(VisibleString)"},
            {R"([APPLICATION 3] IMPLICIT Type1)"},
            {R"([2] EXPLICIT Type2)"},
            {R"(REAL)"},
            {R"(SEQUENCE {id VisibleString})"},
            {R"(INTEGER {homeOffice(0), fieldOffice(1), roving(2)})"},
            {R"(BIT STRING {read(0), write(1), execute(2)})"},
            {R"(BIT STRING)"},
            {R"(OCTET STRING)"},
            {R"(OBJECT IDENTIFIER)"},
            {R"(RELATIVE-OID)"},
            {R"(UTCTime)"},
            {R"(GeneralizedTime)"},
            {R"(ENUMERATED {red(0), green(1), blue(2)})"},
            {R"(SEQUENCE {})"},
            {R"(SEQUENCE {name VisibleString, ok BOOLEAN})"},
            {R"(SEQUENCE {name [0] IMPLICIT VisibleString})"},
            {R"(SEQUENCE {name VisibleString, age INTEGER DEFAULT 20})"},
            {R"(SEQUENCE {inner SEQUENCE {name VisibleString}})"},
            {R"(SEQUENCE {inner [0] EXPLICIT SEQUENCE {name VisibleString}})"},
            {R"(SEQUENCE {inner SEQUENCE {child SEQUENCE {name VisibleString}}})"},
            {R"(SEQUENCE OF INTEGER)"},
            {R"(SET {z BOOLEAN, a INTEGER})"},
            {R"(CHOICE {i INTEGER, s VisibleString})"},
            {R"(CHOICE {i [0] IMPLICIT INTEGER, s [1] IMPLICIT VisibleString})"},
            {R"([0] EXPLICIT CHOICE {i INTEGER, s VisibleString})"},
            {R"(SEQUENCE {id CHOICE {num INTEGER, name VisibleString}})"},
            {R"(SEQUENCE {id INTEGER, data ANY})"},
            {R"(SEQUENCE {name VisibleString, title [0] VisibleString OPTIONAL})"},
            {R"(SEQUENCE {age INTEGER (0..120), name UTF8String (SIZE(1..20))})"},
            {R"([APPLICATION 1] IMPLICIT SEQUENCE { givenName VisibleString, initial VisibleString, familyName VisibleString})"},
            //
            {R"(SET OF INTEGER)"},
            {R"(Names ::= SET OF VisibleString)"},
            {R"(SET OF VisibleString)"},
            {R"(Numbers ::= SET OF INTEGER)"},
            //
            {R"(name VisibleString)"},
            {R"([APPLICATION 30])"},
        };

        for (const auto& entry : table) {
            std::vector<parser_token> tokens;

            lexical_context context;
            lex.parse(context, entry.notation);

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
                        ret = false;  // stop at comments
                        break;
                    default: {
                        tokens.push_back({type, token});
                    }
                }
                _logger->writeln("[%03u] line %zi type %d(%s) index %d pos %zi len %zi (%.*s)", cnt++, desc->line, desc->type, lex.nameof_token(desc->type).c_str(),
                                 desc->index, desc->pos, desc->size, (unsigned)desc->size, desc->p);
                return ret;
            };
            context.for_each(lambda);
            tokens.push_back({token_eof, "$"});

            parse_tree pt;
            ret = lalr.parse(tokens, &pt);

            {
                _logger->colorln("parse tree - re-trace");
                uint32 idx = 0;
                auto lambda = [&idx](parser_action_t type, parse_treenode* node) -> void {
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

            _logger->writeln("LALR parsing %s.", (errorcode_t::success == ret) ? "completed successfully" : "failed");
            _test_case.test(ret, __FUNCTION__, "parse %s", entry.notation);
        }
    }
    __finally2 {}
}

void testcase_parser() {
    test_options();
    test_lexical();
    test_lalr();
}
