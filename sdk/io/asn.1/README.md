## references

* X.680-X.693 : Information Technology - Abstract Syntax Notation One (ASN.1) & ASN.1 encoding rules
  * https://www.itu.int/rec/T-REC-X.680-X.693-202102-I/en
  * Recommendation X.680-X.693 (02/21)

* ASN.1 (Abstract Syntax Notation One) is the international standard for representing data types and structures.
  * https://obj-sys.com/asn1tutorial/asn1only.html
  * ITU-T X.680 ISO/IEC 8824-1 Abstract Syntax Notation One (ASN.1): Specification of basic notation
  * ITU-T X.681 ISO/IEC 8824-2 Abstract Syntax Notation One (ASN.1): Information object specification
  * ITU-T X.682 ISO/IEC 8824-3 Abstract Syntax Notation One (ASN.1): Constraint specification
  * ITU-T X.683 ISO/IEC 8824-4 Abstract Syntax Notation One (ASN.1): Parameterization of ASN.1 specifications
  * ITU-T X.690 ISO/IEC 8825-1 ASN.1 encoding rules: Specification of Basic Encoding Rules (BER), Canonical Encoding Rules (CER) and Distinguished Encoding Rules (DER)
  * ITU-T X.691 ISO/IEC 8825-2 ASN.1 encoding rules: Specification of Packed Encoding Rules (PER)
  * ITU-T X.692 ISO/IEC 8825-3 ASN.1 encoding rules: Specification of Encoding Control Notation (ECN)
  * ITU-T X.693 ISO/IEC 8825-4 ASN.1 encoding rules: XML Encoding Rules (XER)


## ITU-T X.680

```
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
ConstraintSpec ::= SubtypeConstraint | GeneralConstraint
```