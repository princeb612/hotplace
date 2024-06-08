/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * studying
 *  ITU-T X.690 ... real not yet
 *  parser ... in progress
 */

#include <algorithm>
#include <functional>
#include <sdk/io/asn.1/asn1.hpp>
#include <sdk/sdk.hpp>

using namespace hotplace;
using namespace hotplace::io;
using namespace hotplace::net;

test_case _test_case;
t_shared_instance<logger> _logger;

typedef struct _OPTION {
    int verbose;

    _OPTION() : verbose(0) {
        // do nothing
    }
} OPTION;
t_shared_instance<cmdline_t<OPTION>> _cmdline;

#define TESTVECTOR_ENTRY(e1, e2) \
    { e1, e2 }
#define TESTVECTOR_ENTRY3(e1, e2, e3) \
    { e1, e2, e3 }

// X.690 8.1.3 Length octets
void x690_8_1_3_length_octets() {
    struct testvector {
        uint32 i;
        const char* expect;
    } _table[] = {
        TESTVECTOR_ENTRY(38, "26"),
        TESTVECTOR_ENTRY(201, "81 c9"),
        TESTVECTOR_ENTRY(127, "7f"),
        TESTVECTOR_ENTRY(128, "81 80"),
    };

    binary_t bin;

    auto encode_length_octet_routine = [&](const testvector& entry, binary_t& bin) -> void { t_asn1_encode_length<uint32>(bin, entry.i); };

    for (auto entry : _table) {
        encode_length_octet_routine(entry, bin);
        bool test = (bin == base16_decode_rfc(entry.expect));
        _test_case.assert(test, __FUNCTION__, "X.690 8.1.3 length octets %i", entry.i);
        bin.clear();
    }
}

// X.690 8.1.5 end-of-contents octets
void x690_8_1_5_end_of_contents() {
    asn1_encode enc;
    binary_t bin;
    enc.end_contents(bin);
    _logger->dump(bin);
    _test_case.assert(bin == base16_decode("0000"), __FUNCTION__, "X.690 8.1.5 end-of-contents octets");
}

void test_x690_encoding() {
    struct testvector {
        variant var;
        const char* expect;
        const char* text;
    } _table[] = {
        TESTVECTOR_ENTRY3(variant(), "05 00", "X.690 8.8 encoding of a null value"),
        TESTVECTOR_ENTRY3(variant(true), "0101ff", "X.690 8.2 encoding of a boolean value (true)"),
        TESTVECTOR_ENTRY3(variant(false), "010100", "X.690 8.2 encoding of a boolean value (false)"),
        TESTVECTOR_ENTRY3(variant(0), "02 01 00", "X.690 8.3"),
        TESTVECTOR_ENTRY3(variant(127), "02 01 7F", "X.690 8.3"),
        TESTVECTOR_ENTRY3(variant(128), "02 02 00 80", "X.690 8.3"),
        TESTVECTOR_ENTRY3(variant(256), "02 02 01 00", "X.690 8.3"),
        TESTVECTOR_ENTRY3(variant(300), "02 02 01 2C", "X.690 8.3"),
        TESTVECTOR_ENTRY3(variant(65535), "02 03 00 FF FF", "X.690 8.3"),
        TESTVECTOR_ENTRY3(variant(-1), "02 01 FF", "X.690 8.3"),
        TESTVECTOR_ENTRY3(variant(-128), "02 01 80", "X.690 8.3"),
        TESTVECTOR_ENTRY3(variant(-129), "02 02 FF 7F", "X.690 8.3"),
        TESTVECTOR_ENTRY3(variant(-256), "02 02 FF 00", "X.690 8.3"),
        TESTVECTOR_ENTRY3(variant(-257), "02 02 FE FF", "X.690 8.3"),
        TESTVECTOR_ENTRY3(variant(-300), "02 02 FE D4", "X.690 8.3"),
        TESTVECTOR_ENTRY3(variant(-32768), "02 02 80 00", "X.690 8.3"),
        TESTVECTOR_ENTRY3(variant(-32769), "02 03 FF 7F FF", "X.690 8.3"),

        // not yet
        // TESTVECTOR_ENTRY3(variant(1.23), "09 03 80 00 3F 9D 70", "X.690 8.5"),
        // TESTVECTOR_ENTRY3(variant(-1.23), "09 03 C0 00 3F 9D 70", "X.690 8.5"),
        // TESTVECTOR_ENTRY3(variant(0.0), "09 00", "X.690 8.5"),
        // TESTVECTOR_ENTRY3(variant(fp32_from_binary32(0x7f800000)), "09 01 40", "X.690 8.5 Inf"),
        // TESTVECTOR_ENTRY3(variant(fp32_from_binary32(0xff800000)), "09 01 41", "X.690 8.5 -Inf"),
        // TESTVECTOR_ENTRY3(variant(fp32_from_binary32(0x7fc00000)), "09 01 42", "X.690 8.5 NaN"),
        // TESTVECTOR_ENTRY3(variant(123.45), "09 05 80 02 3F F6 E6 66", "X.690 8.5"),
        // TESTVECTOR_ENTRY3(variant(12345.6789), "09 09 80 00 00 03 40 E6 B7 27 0A 14 7A E1", "X.690 8.5"),
        // TESTVECTOR_ENTRY3(variant(-0.000012345), "09 09 C0 FF FF FC 3D CC CC CC CC CC CC CD", "X.690 8.5"),

    };

    binary_t bin;
    asn1_encode enc;

    auto encode_routine = [&](binary_t& bin, const variant& v) -> void { enc.encode(bin, v); };

    for (auto entry : _table) {
        encode_routine(bin, entry.var);
        _logger->dump(bin);
        _test_case.assert(bin == base16_decode_rfc(entry.expect), __FUNCTION__, "X.690 expect [%s] %s", entry.expect, entry.text);
        bin.clear();
    }
}

// X.690 8.6 encoding of a bitstring value
// commencing with the leading bit and proceeding to the trailing bit
void x690_8_6_bitstring() {
    // sketch - pseudo code
    // if(size(input) % 2) { pad = '0'; padbit = 4; }
    // encode(asn1_tag_bitstring).encode(padbit).encode(input).encode(pad)

    // primitive
    {
        binary_t bin;
        asn1_encode enc;
        enc.bitstring(bin, "0A3B5F291CD");
        _logger->dump(bin);
        _test_case.assert(bin == base16_decode("0307040A3B5F291CD0"), __FUNCTION__, "X.690 8.6.4 BitString");
    }

    // constructed
    {
        binary bin;
        bin.push_back(asn1_tag_bitstring | asn1_tag_constructed);
        bin.push_back(0x80);
        bin.push_back(asn1_tag_bitstring);
        t_asn1_encode_length<uint32>(bin.get(), 3);
        bin.append(base16_decode("000a3b"));
        bin.push_back(asn1_tag_bitstring);
        t_asn1_encode_length<uint32>(bin.get(), 5);
        bin.append(base16_decode("045f291cd0"));
        bin.push_back(0x00);  // EOC
        bin.push_back(0x00);  // EOC
        _logger->dump(bin.get());
        const char* expect_constructed = "23 80 03 03 00 0A 3B 03 05 04 5F 29 1C D0 00 00";
        _test_case.assert(bin.get() == base16_decode_rfc(expect_constructed), __FUNCTION__, "X.690 8.6.4 BitString constructed");
    }
}

// X.690 8.8 encoding of a null value
// void x690_8_8_null() {
//     binary_t bin;
//     asn1_encode enc;
//     enc.null(bin);
//
//     _logger->dump(bin);
//     _test_case.assert(bin == base16_decode("0500"), __FUNCTION__, "X.690 8.8 null");
// }

// X.690 8.9 encoding of a sequence value
void x690_8_9_sequence() {
    // SEQUENCE {name IA5String, ok BOOLEAN}
    // {name "Smith", ok TRUE}
    binary_t bin;
    asn1_encode enc;
    enc.ia5string(bin, "Smith");
    enc.primitive(bin, true);

    size_t size = bin.size();
    bin.insert(bin.begin(), size);                         // 0xa
    bin.insert(bin.begin(), asn1_tag_constructed | 0x10);  // asn1_tag_sequence

    // Sequence Length  Contents
    // 30_16    0A_16
    //                  IA5String  Length  Contents
    //                  16_16      05_16   "Smith"
    //                  Boolean    Length  Contents
    //                  01_16      01_16   FF_16

    // 30 = 0011 0000 primitive, constructed

    _logger->dump(bin);
    _test_case.assert(bin == base16_decode_rfc("30 0A 16 05 53 6D 69 74 68 01 01 FF"), __FUNCTION__, "X.690 8.9 Sequence");
}

// X.690 8.14 encoding of a tagged value
void x690_8_14_tagged() {
    asn1_encode enc;
    binary_t bin_type1;
    binary_t bin_type2;
    binary_t bin_type3;
    binary_t bin_type4;
    binary_t bin_type5;
    // Type1 ::= VisibleString
    {
        enc.visiblestring(bin_type1, "Jones");
        _logger->dump(bin_type1);
        _test_case.assert(bin_type1 == base16_decode_rfc("1A 05 4A 6F 6E 65 73"), __FUNCTION__, "X.690 8.14 tagged # type1");
    }
    // Type2 ::= [Application 3] implicit Type1
    {
        enc.encode(bin_type2, asn1_tag_application, 3, "Jones");
        _logger->dump(bin_type2);
        _test_case.assert(bin_type2 == base16_decode_rfc("43 05 4A 6F 6E 65 73"), __FUNCTION__, "X.690 8.14 tagged # type2");
    }
    // Type3 ::= [2] Type2
    {
        // enc.encode(bin_type3, asn1_tag_context | asn1_tag_constructed, 2);
        binary_push(bin_type3, asn1_tag_context | asn1_tag_constructed | 2);
        t_asn1_encode_length<uint32>(bin_type3, bin_type2.size());
        binary_append(bin_type3, bin_type2);
        _logger->dump(bin_type3);
        _test_case.assert(bin_type3 == base16_decode_rfc("a2 07 43 05 4A 6F 6E 65 73"), __FUNCTION__, "X.690 8.14 tagged # type3");
    }
    // Type4 ::= [Application 7] implicit Type3
    {
        binary_push(bin_type4, asn1_tag_application | asn1_tag_constructed | 7);
        t_asn1_encode_length<uint32>(bin_type4, bin_type2.size());
        binary_append(bin_type4, bin_type2);  // ?? not bin_type3
        _logger->dump(bin_type4);
        _test_case.assert(bin_type4 == base16_decode_rfc("67 07 43 05 4A 6F 6E 65 73"), __FUNCTION__, "X.690 8.14 tagged # type4");
    }
    // Type5 ::= [2] implicit Type2
    {
        binary_push(bin_type5, asn1_tag_context | 2);
        t_asn1_encode_length<uint32>(bin_type5, 5);
        binary_append(bin_type5, "Jones");
        _logger->dump(bin_type5);
        _test_case.assert(bin_type5 == base16_decode_rfc("82 05 4A 6F 6E 65 73"), __FUNCTION__, "X.690 8.14 tagged # Type5");
    }
}

// X.690 8.19 encoding of an object identifier value
void x690_8_19_objid() {
    struct testvector {
        std::pair<oid_t, std::string> couple;
    } _table[] = {
        std::make_pair(oid_t{1, 3, 6, 1, 4, 1}, "06 05 2b 06 01 04 01"),
        std::make_pair(oid_t{1, 2, 840, 113549}, "06 06 2A 86 48 86 F7 0d"),
        std::make_pair(oid_t{1, 3, 6, 1, 4, 1, 311, 21, 20}, "06 09 2b 06 01 04 01 82 37 15 14"),
        std::make_pair(oid_t{1, 3, 6, 1, 4, 1, 311, 60, 2, 1, 1}, "06 0B 2B 06 01 04 01 82 37 3C 02 01 01"),
        std::make_pair(oid_t{1, 2, 840, 10045, 3, 1, 7}, "06 08 2a 86 48 ce 3d 03 01 07"),
        std::make_pair(oid_t{2, 100, 3}, "06 03 81 34 03"),  // 0..39 < 100 ??
    };

    binary_t bin;
    asn1_encode enc;

    auto encode_oid_routine = [&](const oid_t& oid, binary_t& bin) -> void { enc.primitive(bin, oid); };

    for (auto entry : _table) {
        const std::string& expect = entry.couple.second;
        encode_oid_routine(entry.couple.first, bin);
        _logger->dump(bin);
        _test_case.assert(bin == base16_decode_rfc(expect), __FUNCTION__, "X.690 8.19 object identifier expect %s", expect.c_str());
        bin.clear();
    }
}

// X.690 8.20 encoding of a relative object identifier value
void x690_8_20_relobjid() {
    struct testvector {
        std::pair<reloid_t, std::string> couple;
    } _table[] = {
        std::make_pair(reloid_t{8571, 3, 2}, "0D 04 C27B0302"),
    };

    binary_t bin;
    asn1_encode enc;
    auto encode_reloid_routine = [&](const reloid_t& reloid, binary_t& bin) -> void { enc.primitive(bin, reloid); };

    for (auto entry : _table) {
        const std::string& expect = entry.couple.second;
        encode_reloid_routine(entry.couple.first, bin);
        _logger->dump(bin);
        _test_case.assert(bin == base16_decode_rfc(expect), __FUNCTION__, "X.690 8.20 relative object identifier expect %s", expect.c_str());
        bin.clear();
    }
}

// X.690 8.21.5.4 Example Name ::= VisibleString
void x690_8_21_visiblestring() {
    binary_t bin;
    asn1_encode enc;
    enc.visiblestring(bin, "Jones");
    _logger->dump(bin);
    _test_case.assert(bin == base16_decode_rfc("1a 05 4a6f6e6573"), __FUNCTION__, "X.690 8.21 VisibleString");
}

void x690_11_7_generallizedtime() {
    struct testvector {
        std::pair<datetime_t, basic_stream> couple;
    } _table[] = {
        std::make_pair(datetime_t(1992, 5, 21, 0, 0, 0), "19920521000000Z"),
        std::make_pair(datetime_t(1992, 6, 22, 12, 34, 21), "19920622123421Z"),
        std::make_pair(datetime_t(1992, 7, 22, 13, 21, 00, 3), "19920722132100.3Z"),
    };

    asn1_encode enc;
    basic_stream bs;

    auto encode_generalizedtime_routine = [&](const datetime_t& d, basic_stream& bs) -> void { enc.generalized_time(bs, d); };

    for (auto entry : _table) {
        const basic_stream& expect = entry.couple.second;
        encode_generalizedtime_routine(entry.couple.first, bs);
        _logger->dump(bs);
        _test_case.assert(bs == expect, __FUNCTION__, "X.690 11.7 generalized time expect %s", expect.c_str());
        bs.clear();
    }
}

void x690_annex_a() {
    //
}

void test_asn1_typedef_value() {
    // skeleton .. o
    // implement members .. o
    asn1 notation;
    auto node_personal = new asn1_set("PersonnelRecord", new asn1_tagged(asn1_class_application, 0, asn1_implicit));
    *node_personal << new asn1_namedtype("name", new asn1_type_defined("Name"))
                   << new asn1_namedtype("title", new asn1_type(asn1_type_visiblestring, new asn1_tagged(asn1_class_empty, 0)))
                   << new asn1_namedtype("number", new asn1_type_defined("EmployeeNumber"))
                   << new asn1_namedtype("dateOfHire", new asn1_type_defined("Date", new asn1_tagged(asn1_class_empty, 1)))
                   << new asn1_namedtype("nameOfSpouse", new asn1_type_defined("Name", new asn1_tagged(asn1_class_empty, 2)))
                   << new asn1_namedtype("children",
                                         &(new asn1_sequence_of("ChildInformation", new asn1_tagged(asn1_class_empty, 3, asn1_implicit)))->set_default());
    notation << node_personal;

    auto node_childinfo = new asn1_set("ChildInformation");
    *node_childinfo << new asn1_namedtype("name", new asn1_type_defined("Name"))
                    << new asn1_namedtype("dateOfBirth", new asn1_type_defined("Date", new asn1_tagged(asn1_class_empty, 0)));
    notation << node_childinfo;

    auto node_name = new asn1_sequence("Name", new asn1_tagged(asn1_class_application, 1, asn1_implicit));
    *node_name << new asn1_namedtype("givenName", new asn1_type(asn1_type_visiblestring))
               << new asn1_namedtype("initial", new asn1_type(asn1_type_visiblestring))
               << new asn1_namedtype("familyName", new asn1_type(asn1_type_visiblestring));
    notation << node_name;

    auto node_employeenumber = new asn1_namedobject("EmployeeNumber", asn1_type_integer, new asn1_tagged(asn1_class_application, 2, asn1_implicit));
    notation << node_employeenumber;

    auto node_date = new asn1_namedobject("Date", asn1_type_visiblestring, new asn1_tagged(asn1_class_application, 3, asn1_implicit));
    notation << node_date;

    basic_stream bs;
    notation.publish(&bs);
    _logger->write(bs);
    _test_case.assert(true, __FUNCTION__, "publish definition");

    binary_t bin;
    auto data_personal = notation.clone("PersonnelRecord");
    // data_personal->get_namedvalue("name") << "John" << "P" << "Smith";
    // data_personal->get_namedvalue("title") << "Director";
    // data_personal->get_namedvalue("number") << 51;
    // data_personal->get_namedvalue("dateOfHire") << "19710917";
    // data_personal->get_namedvalue("nameOfSpouse") << "Mary" << "T" << "Smith";
    // data_personal->get_namedvalue("children").spawn() << "Ralph" << "T" << "Smith";
    // data_personal->get_namedvalue("children").spawn() << "Susan" << "B" << "Jones";
    notation.publish(&bin);
    data_personal->release();
    _test_case.assert(true, __FUNCTION__, "publish value");
}

void test_asn1_parse() {
    _test_case.begin("rule");
    asn1 a1;
    // ITU-T X.680
    a1.add_rule(R"a(
        -- 16 Definition of types and values
        Type ::= BuiltinType | ReferencedType | ConstrainedType
        BuiltinType ::= BitStringType
            | BooleanType
            | CharacterStringType
            | ChoiceType
            | EmbeddedPDVType
            | EnumeratedType
            | ExternalType
            | InstanceOfType
            | IntegerType
            | NullType
            | ObjectClassFieldType
            | ObjectIdentifierType
            | OctetStringType
            | RealType
            | RelativeOIDType
            | SequenceType
            | SequenceOfType
            | SetType
            | SetOfType
            | TaggedType
        ReferencedType ::= DefinedType | UsefulType | SelectionType | TypeFromObject | ValueSetFromObjects
        NamedType ::= identifier Type
        Value ::= BuiltinValue | ReferencedValue | ObjectClassFieldValue
        BuiltinValue ::= BitStringValue | BooleanValue | CharacterStringValue | ChoiceValue | EmbeddedPDVValue | EnumeratedValue | ExternalValue
            | InstanceOfValue | IntegerValue | NullValue | ObjectIdentifierValue | OctetStringValue | RealValue | RelativeOIDValue | SequenceValue
            | SequenceOfValue | SetValue | SetOfValue | TaggedValue
        ReferencedValue ::= DefinedValue | ValueFromObject
        NamedValue ::= identifier Value
        -- ITU-T X.680 17
        BooleanType ::= BOOLEAN
        BooleanValue ::= TRUE | FALSE
        -- ITU-T X.680 18
        IntegerType ::= INTEGER | INTEGER "{" NamedNumberList "}"
        NamedNumberList ::= NamedNumber | NamedNumberList "," NamedNumber
        NamedNumber ::= identifier "(" SignedNumber ")" | identifier "(" DefinedValue ")"
        SignedNumber ::= number | "-" number
        IntegerValue ::= SignedNumber | identifier
        -- ITU-T X.680 19
        EnumeratedType ::= ENUMERATED "{" Enumerations "}"
        Enumerations ::=
            RootEnumeration
            | RootEnumeration "," "..." ExceptionSpec
            | RootEnumeration "," "..." ExceptionSpec "," AdditionalEnumeration
        RootEnumeration ::= Enumeration
        AdditionalEnumeration ::= Enumeration
        Enumeration ::= EnumerationItem | EnumerationItem "," Enumeration
        EnumerationItem ::= identifier | NamedNumber
        -- ITU-T X.680 20
        RealType ::= REAL
        -- 20.5 SEQUENCE { mantissa INTEGER, base INTEGER (2|10), exponent INTEGER }
        RealValue ::= NumericRealValue | SpecialRealValue
        NumericRealValue ::=
            realnumber
            | "-" realnumber
            | SequenceValue -- Value of the associated sequence type
        SpecialRealValue ::= PLUS-INFINITY | MINUS-INFINITY
        -- ITU-T X.680 21
        BitStringType ::= BIT STRING | BIT STRING "{" NamedBitList "}"
        NamedBitList ::= NamedBit | NamedBitList "," NamedBit
        NamedBit ::= identifier "(" number ")" | identifier "(" DefinedValue ")"
        BitStringValue ::=
            bstring
            | hstring
            | "{" IdentifierList "}"
            | "{" "}"
            | CONTAINING Value
        IdentifierList ::= identifier | IdentifierList "," identifier
        -- ITU-T X.680 22
        OctetStringType ::= OCTET STRING
        OctetStringValue ::= bstring | hstring | CONTAINING Value
        -- ITU-T X.680 23
        NullType ::= NULL
        NullValue ::= NULL
        -- ITU-T X.680 24
        SequenceType ::=
            SEQUENCE "{" "}"
            | SEQUENCE "{" ExtensionAndException OptionalExtensionMarker "}"
            | SEQUENCE "{" ComponentTypeLists "}"
        ExtensionAndException ::= "..." | "..." ExceptionSpec
        OptionalExtensionMarker ::= "," "..." | empty
        ComponentTypeLists ::=
            RootComponentTypeList
            | RootComponentTypeList "," ExtensionAndException ExtensionAdditions OptionalExtensionMarker
            | RootComponentTypeList "," ExtensionAndException ExtensionAdditions ExtensionEndMarker "," RootComponentTypeList
            | ExtensionAndException ExtensionAdditions ExtensionEndMarker "," RootComponentTypeList
            | ExtensionAndException ExtensionAdditions OptionalExtensionMarker
        RootComponentTypeList ::= ComponentTypeList
        ExtensionEndMarker ::= "," "..."
        ExtensionAdditions ::= "," ExtensionAdditionList | empty
        ExtensionAdditionList ::=
            ExtensionAddition
            | ExtensionAdditionList "," ExtensionAddition
        ExtensionAddition ::=
            ComponentType
            | ExtensionAdditionGroup
        ExtensionAdditionGroup ::= "[[" VersionNumber ComponentTypeList "]]"
        VersionNumber ::= empty | number ":"
        ComponentTypeList ::=
            ComponentType
            | ComponentTypeList "," ComponentType
        ComponentType ::=
            NamedType
            | NamedType OPTIONAL
            | NamedType DEFAULT Value
            | COMPONENTS OF Type
        SequenceValue ::=
            "{" ComponentValueList "}"
            | "{" "}"
        ComponentValueList ::=
            NamedValue
            | ComponentValueList "," NamedValue
        -- ITU-T X.680 25
        SequenceOfType ::= SEQUENCE OF Type | SEQUENCE OF NamedType
        SequenceOfValue ::=
            "{" ValueList "}"
            | "{" NamedValueList "}"
            | "{" "}"
        ValueList ::= Value | ValueList "," Value
        NamedValueList ::= NamedValue | NamedValueList "," NamedValue
        -- ITU-T X.680 26
        SetType ::=
            SET "{" "}"
            | SET "{" ExtensionAndException OptionalExtensionMarker "}"
            | SET "{" ComponentTypeLists "}"
        SetValue ::=
            "{" ComponentValueList "}"
            | "{" "}"
        -- ITU-T X.680 27
        SetOfType ::= SET OF Type | SET OF NamedType
        SetOfValue ::=
            "{" ValueList "}"
            | "{" NamedValueList "}"
            | "{" "}"
        -- ITU-T X.680 28
        ChoiceType ::= CHOICE "{" AlternativeTypeLists "}"
        AlternativeTypeLists ::=
            RootAlternativeTypeList
            | RootAlternativeTypeList "," ExtensionAndException ExtensionAdditionAlternatives OptionalExtensionMarker
        RootAlternativeTypeList ::= AlternativeTypeList
        ExtensionAdditionAlternatives ::= "," ExtensionAdditionAlternativesList | empty
        ExtensionAdditionAlternativesList ::=
            ExtensionAdditionAlternative
            | ExtensionAdditionAlternativesList "," ExtensionAdditionAlternative
        ExtensionAdditionAlternative ::= ExtensionAdditionAlternativesGroup | NamedType
        ExtensionAdditionAlternativesGroup ::= "[[" VersionNumber AlternativeTypeList "]]"
        AlternativeTypeList ::= NamedType | AlternativeTypeList "," NamedType
        -- ITU-T X.680 29
        SelectionType ::= identifier "<" Type
        -- ITU-T X.680 30
        TaggedType ::=
            Tag Type
            | Tag IMPLICIT Type
            | Tag EXPLICIT Type
        Tag ::= "[" Class ClassNumber "]"
        ClassNumber ::= number | DefinedValue
        Class ::=
            UNIVERSAL
            | APPLICATION
            | PRIVATE
            | empty
        TaggedValue ::= Value
        -- ITU-T X.680 31
        ObjectIdentifierType ::= OBJECT IDENTIFIER
        ObjectIdentifierValue ::=
            "{" ObjIdComponentsList "}"
            | "{" DefinedValue ObjIdComponentsList "}"
        ObjIdComponentsList ::= ObjIdComponents | ObjIdComponents ObjIdComponentsList
        ObjIdComponents ::= NameForm | NumberForm | NameAndNumberForm | DefinedValue
        NameForm ::= identifier
        NumberForm ::= number | DefinedValue
        NameAndNumberForm ::= identifier "(" NumberForm ")"
        -- ITU-T X.680 32
        RelativeOIDValue ::= "{" RelativeOIDComponentsList "}"
        RelativeOIDComponentsList ::= RelativeOIDComponents | RelativeOIDComponents RelativeOIDComponentsList
        RelativeOIDComponents ::= NumberForm | NameAndNumberForm | DefinedValue
        -- ITU-T X.680 33
        EmbeddedPDVType ::= EMBEDDED PDV
        EmbeddedPdvValue ::= SequenceValue -- value of associated type defined in 33.5
        -- ITU-T X.680 36
        CharacterStringType ::= RestrictedCharacterStringType | UnrestrictedCharacterStringType
        CharacterStringValue ::= RestrictedCharacterStringValue | UnrestrictedCharacterStringValue
        -- ITU-T X.680 37
        RestrictedCharacterStringType ::=
            BMPString
            | GeneralString
            | GraphicString
            | IA5String
            | ISO646String
            | NumericString
            | PrintableString
            | TeletexString
            | T61String
            | UniversalString
            | UTF8String
            | VideotexString
            | VisibleString
        -- Table 6 List of restricted character string types
        -- Table 7 NumericString
        -- Table 8 PrintableString
        RestrictedCharacterStringValue ::= cstring | CharacterStringList | Quadruple | Tuple
        CharacterStringList ::= "{" CharSyms "}"
        CharSyms ::= CharsDefn | CharSyms "," CharsDefn
        CharsDefn ::= cstring | Quadruple | Tuple | DefinedValue
        Quadruple ::= "{" Group "," Plane "," Row "," Cell "}"
        Group ::= number
        Plane ::= number
        Row ::= number
        Cell ::= number
        Tuple ::= "{" TableColumn "," TableRow "}"
        TableColumn ::= number
        TableRow ::= number
        -- ITU-T X.680 42
        GeneralizedTime ::= [UNIVERSAL 24] IMPLICIT VisibleString
        -- ITU-T X.680 43
        UTCTime ::= [UNIVERSAL 23] IMPLICIT VisibleString
        -- ITU-T X.680 45
        ConstrainedType ::= Type Constraint | TypeWithConstraint
        TypeWithConstraint ::=
            SET Constraint OF Type
            | SET SizeConstraint OF Type
            | SEQUENCE Constraint OF Type
            | SEQUENCE SizeConstraint OF Type
            | SET Constraint OF NamedType
            | SET SizeConstraint OF NamedType
            | SEQUENCE Constraint OF NamedType
            | SEQUENCE SizeConstraint OF NamedType
        Constraint ::= "(" ConstraintSpec ExceptionSpec ")"
        ConstraintSpec ::= SubtypeConstraint | GeneralConstraint)a");

    basic_stream bs;
    a1.learn();
    a1.get_parser().dump(a1.get_rule_context(), bs);
    _logger->write(bs);

    // TODO

    _test_case.assert(true, __FUNCTION__, "rule");
}

int main(int argc, char** argv) {
#ifdef __MINGW32__
    setvbuf(stdout, 0, _IOLBF, 1 << 20);
#endif

    _cmdline.make_share(new cmdline_t<OPTION>);
    *_cmdline << cmdarg_t<OPTION>("-v", "verbose", [](OPTION& o, char* param) -> void { o.verbose = 1; }).optional();
    _cmdline->parse(argc, argv);

    const OPTION& option = _cmdline->value();

    logger_builder builder;
    builder.set(logger_t::logger_stdout, option.verbose).set(logger_t::logger_flush_time, 0).set(logger_t::logger_flush_size, 0);
    _logger.make_share(builder.build());

    // studying ...
    x690_8_1_3_length_octets();
    x690_8_1_5_end_of_contents();
    test_x690_encoding();
    // x690_8_2_boolean();
    // x690_8_3_integer();
    // x690_8_5_real();
    x690_8_6_bitstring();
    // x690_8_8_null();
    x690_8_9_sequence();
    x690_8_14_tagged();
    x690_8_19_objid();
    x690_8_20_relobjid();
    x690_8_21_visiblestring();
    x690_11_7_generallizedtime();
    x690_annex_a();
    test_asn1_typedef_value();
    test_asn1_parse();

    _logger->flush();

    _test_case.report(5);
    _cmdline->help();
    return _test_case.result();
}
