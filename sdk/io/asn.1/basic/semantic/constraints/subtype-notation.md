## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1104                    │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```
# Subtype Notation and Value Sets

## 1. Role

* https://obj-sys.com/asn1tutorial/node18.html

````
SingleValue:
Divisors-of-6 ::= INTEGER (1 | 2 | 3 | 6)

ContainedSubtype:
Divisors-of-18 ::= INTEGER (INCLUDES Divisors-of-6 | 9 | 18)

ValueRange:
TeenAgeYears ::= (13 .. 19)

Permitted Alphabet:
BooleanValue ::= IA5String (FROM ('T' | 'F'))

SizeConstraint:
BaseballTeamRoster ::= SET SIZE (1..25) OF PlayerNames
````

| Type              | SV | CS | VR | SR | AL | IS |
| --                | -- | -- | -- | -- | -- | -- |
| Boolean           | Y  | Y  | N  | N  | N  | N  |
| Integer           | Y  | Y  | Y  | N  | N  | N  |
| Enumerated        | Y  | Y  | N  | N  | N  | N  |
| Real              | Y  | Y  | Y  | N  | N  | N  |
| Object Identifier | Y  | Y  | N  | N  | N  | N  |
| Bit String        | Y  | Y  | N  | Y  | N  | N  |
| Octet String      | Y  | Y  | N  | Y  | N  | N  |
| Character String  | Y  | Y  | N  | Y  | Y  | N  |
| Sequence          | Y  | Y  | N  | N  | N  | Y  |
| Sequence-of       | Y  | Y  | N  | Y  | N  | Y  |
| Set               | Y  | Y  | N  | N  | N  | Y  |
| Set-of            | Y  | Y  | N  | Y  | N  | Y  |
| Any               | Y  | Y  | N  | N  | N  | N  |
| Choice            | Y  | Y  | N  | N  | N  | Y  |

SV : Single Value
CS : Contained SubType
VR : Value Range
SR : Size Range
AL : Alphabet Limitation
IS : Inner Substring

## 2. Model

The existing implementation notes are retained below; see the references for the concrete source files.

## 3. Important behavior and lifetime

No separate lifetime or behavior contract was stated in the existing notes beyond the material retained below.

## 4. Example from the source tests

No dedicated source-test example was documented in the existing notes. See the linked test sources, where present.

## 5. Relationships

Related modules and boundaries are recorded below where identified in the existing notes.

## 6. References

Source references and related documents are retained below where available.
