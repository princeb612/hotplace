## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 2 · Revision 1105                    │
│ Source basis: Revision 1105                  │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```
# ASN.1 Basic

## 1. Role

`asn.1/basic` contains the ASN.1 type/tag/constraint definitions, semantic and structural node models, parameterized-type support, and visitor interfaces used by the higher-level loader/runtime. The linked study documents preserve notation and encoding details; this directory is the implementation model, not the grammar parser or runtime module registry.

## 2. Data Model
### Detailed documents

- [Prefixed type encoding](prefixed-type-encoding.md) — X.690 8.14, IMPLICIT/EXPLICIT tagging, and encoding experiments
- [Structural representation](structural/README.md) — structural TLV nodes, semantic objects, and concrete tagging examples
- [Subtype notation](semantic/constraints/subtype-notation.md) — subtype notation and value sets

### Implementation records

- [ASN.1 object model](asn1-object-model.md)
- [ASN.1 structural node model](asn1-node.md)
- [ASN.1 visitor architecture](asn1-visitor.md)
- [ASN.1 semantic constraints](semantic/constraints/asn1_constraints.md)

- `semantic/` — semantic type/object hierarchy
- `structural/` — structural node hierarchy
- `visitor/` — traversal and interpretation visitors

## 3. Behavior Model
Keep semantic and structural representations distinct. Semantic objects capture type/value relationships and constraints; structural nodes represent the parsed notation tree and support traversal/interpretation. Visitors provide a way to process those structures without collapsing every operation into the parser itself. Constraint evaluation and parameterized syntax have their own submodules and should be traced through their specific documents.


## 4. Relationships
### Related areas

- `../runtime/` — runtime ASN.1 types and objects
- `../../parser/` — parser implementation used to construct ASN.1 syntax structures

### Implementation source navigation
- `semantic/` — semantic type/object hierarchy and constraints
- `structural/` — structural node hierarchy
- `visitor/` — traversal/interpretation visitors
- [ASN.1 object model](asn1-object-model.md)
- [Structural node model](asn1-node.md)
- [Visitor architecture](asn1-visitor.md)
- [Constraint evaluator](semantic/constraints/asn1_constraints.md)
- `test/testcase/asn.1/` and `test/testcase/asn.1/runtime/`

## 5. Development Notes

### ASN.1 notation boundary (ITU-T X.680)

This grammar excerpt was retained from the original study note. It is a working reference for notation families that matter when following the parser and semantic model; it is **not** a complete transcription of X.680 or a claim of full conformance. In particular, the excerpt covers type/value families and selected productions from Sections 16–45, including built-in and referenced types, constructed values, tagging, character strings, and constraints. Keep the excerpt intact when reorganizing this note: examples and production details are useful evidence of what the study actually examined.

The production list is not an implementation checklist. A notation may appear here without complete lexer recognition, grammar production, semantic reconstruction, reference resolution, or runtime support. For implementation questions, trace the relevant production through the generic parser, ASN.1 advisor/publisher, semantic objects, and constraint evaluator.

#### Retained grammar excerpt

```asn1
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
