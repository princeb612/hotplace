# ASN.1 parser/encoder

## design concept sketch (draft)


1. parser

```
    handle by word not characters

    a. access text by index

      original text
          Type ::= BuiltinType
          BuiltinType ::= IntegerType
          IntegerType ::= INTEGER

      in the memory
          0               1                2                3               4
          0123456789abcdef0123 456789abcdef0123456789abcdef 0123456789abcdef01234567
          Type ::= BuiltinType\nBuiltinType ::= IntegerType\nIntegerType ::= INTEGER
      dictionary (index 0 reserved, begins at 1)
          1    2   3            3           2   4            4           2   5

      debug) p dictionary
      $1 = {{{"Type", 1}, {"::=", 2}, {"BuiltinType", 3}, {"IntegerType", 4}, {"INTEGER", 5}}
            {{1, "Type"}, {2, "::="}, {3, "BuiltinType"}, {4, "IntegerType"}, {5, "INTEGER"}}}

      debug) p context._tokens
      $2 = {{index=1, pos=0x00, size=4},  {index=2, pos=0x05, size=3}, {index=3, pos=0x09, size=11},
            {index=3, pos=0x15, size=11}, {index=2, pos=0x21, size=3}, {index=4, pos=0x25, size=11},
            {index=4, pos=0x31, size=11}, {index=2, pos=0x3d, size=3}, {index=5, pos=0x41, size=7}}

             lookup(1, word)
      debug) p word
      $3 word = "Type"

             lookup(""Type", index)
      debug) p index
      $4 index = 1

    b. pattern search

      assume pattern_search (pseudo code)
          match_result pattern_search(array(index)) {
              printf("%.*s", size, baseaddr);
              returns {baseaddr, size};
          }

      test vector
          pattern_search(input) | {baseaddr, size}             | stdout
          array(4, 2, 5)        | {baseaddr = 0x31, size = 23} | IntegerType ::= INTEGER
          array(1, 2, 3)        | {baseaddr = 0x00, size = 20} | Type ::= BuiltinType

      cf.
          fulltext.pattern_search("IntegerType ::= INTEGER")
              full-text 74 bytes, patter 23 bytes
              Knuth-Morris-Pratt Algorithm O(74+23)=O(97)

          parser.parse(fulltext)                          ... pre-process : scan(1-phase) and build up(dictionary)
          parser.pattern_search(array(4, 2, 5))
              full-text 9 words, patter 3
              Knuth-Morris-Pratt Algorithm O(9+3)=O(12)   ... process search

    c. directed graph

      t_graph<int> graph;
      graph.add_directed_edge(3, 1).add_directed_edge(4, 3).add_directed_edge(5, 4);

          5->4->3->1
              INTEGER->IntegerType->BuiltinType->Type
          in the same way
              number->IntegerValue->BuiltinValue->Value
```

2. ASN.1 encoder sketch

```
    a. definition

      input
          PersonnelRecord ::= [APPLICATION 0] IMPLICIT SET "{" name Name "}"
          Name ::= [APPLICATION 1] IMPLICIT SEQUENCE "{" givenName VisibleString "}"

      interpretation process
          SET { name Name } -> SET { NamedType } -> SET { ComponentType }
                            -> SET { ComponentTypeList } -> SET { RootComponentTypeList }
                            -> SET { ComponentTypeLists } -> SetType
          APPLICATION -> Class
          [APPLICATION 0]  -> Tag(Class=APPLICATION, ClassNumber=0)
          [APPLICATION 0] IMPLICIT Type -> TaggedType(Tag IMPLICIT Type=SetType) -> BuiltinType -> Type
          PersonnelRecord <- Type

    b. basic implementation

      asn1_object, asn1_set, asn1_sequence, asn1_namedtype, ...

      type
          asn1 notation;
          auto node_personal = new asn1_set("PersonnelRecord", new asn1_tagged(asn1_class_application, 0, asn1_implicit));
          *node_personal << new asn1_namedtype("name", new asn1_type_defined("Name"))
                         << new asn1_namedtype("title", new asn1_type(asn1_type_visiblestring, new asn1_tagged(asn1_class_empty, 0)))
                         << new asn1_namedtype("number", new asn1_type_defined("EmployeeNumber"))
                         << new asn1_namedtype("dateOfHire", new asn1_type_defined("Date", new asn1_tagged(asn1_class_empty, 1)))
                         << new asn1_namedtype("nameOfSpouse", new asn1_type_defined("Name", new asn1_tagged(asn1_class_empty, 2)))
                         << new asn1_namedtype("children", new asn1_sequence_of("ChildInformation", new asn1_tagged(asn1_class_empty, 3, asn1_implicit)));
          notation << node_personal;
    
          auto node_childinfo = new asn1_set("ChildInformation");
          *node_childinfo << new asn1_namedtype("name", new asn1_type_defined("Name"))
                          << new asn1_namedtype("dateOfBirth", new asn1_type_defined("Date", new asn1_tagged(asn1_class_empty, 0)));
          notation << node_childinfo;
    
          auto node_name = new asn1_sequence("Name", new asn1_tagged(asn1_class_application, 1, asn1_implicit));
          *node_name << new asn1_namedtype("givenName", new asn1_type(asn1_type_visiblestring)) << new asn1_namedtype("initial", new asn1_type(asn1_type_visiblestring))
                     << new asn1_namedtype("familyName", new asn1_type(asn1_type_visiblestring));
          notation << node_name;
    
          auto node_employeenumber = new asn1_namedobject("EmployeeNumber", asn1_type_integer, new asn1_tagged(asn1_class_application, 2, asn1_implicit));
          notation << node_employeenumber;
    
          auto node_date = new asn1_namedobject("Date", asn1_type_visiblestring, new asn1_tagged(asn1_class_application, 3, asn1_implicit));
          notation << node_date;
    
     value
          binary_t bin;
          auto data_personal = notation.clone("PersonnelRecord");
          data_personal->get_namedvalue("name") << "John" << "P" << "Smith";
          data_personal->get_namedvalue("title") << "Director";
          data_personal->get_namedvalue("number") << 51;
          data_personal->get_namedvalue("dateOfHire") << "19710917";
          data_personal->get_namedvalue("nameOfSpouse") << "Mary" << "T" << "Smith";
          data_personal->get_namedvalue("children").spawn() << "Ralph" << "T" << "Smith";
          data_personal->get_namedvalue("children").spawn() << "Susan" << "B" << "Jones";
          data_personal->encode(bin);
          data_personal->release();
    
     generate
          node_personal->write_structure(personal_structure); // PersonnelRecord ::= ...
          notation.write_structure(structures);               // see asn1_structure
          data_personal->write_value(values);                 // see asn1_value
    
     parse
          asn1 notation2(asn1_structure);
          asn1 notation3(asn1_structure, asn1_value);
    
          notation2.write_structure(structures);
          notation3.write_structure(structures);
          notation3.write_value(values);
    
     sample data
    
          constexpr char asn1_structure[] =
              R"(PersonnelRecord ::= [APPLICATION 0] IMPLICIT SET {
                      name Name,
                      title [0] VisibleString,
                      number EmployeeNumber,
                      dateOfHire [1] Date,
                      nameOfSpouse [2] Name,
                      children [3] IMPLICIT
                          SEQUENCE OF ChildInformation DEFAULT {} }
    
                  ChildInformation ::= SET
                      { name Name,
                      dateOfBirth [0] Date}
    
                  Name ::= [APPLICATION 1] IMPLICIT SEQUENCE
                      { givenName VisibleString,
                      initial VisibleString,
                      familyName VisibleString}
    
                  EmployeeNumber ::= [APPLICATION 2] IMPLICIT INTEGER
    
                  Date ::= [APPLICATION 3] IMPLICIT VisibleString -- YYYYMMDD)";
    
          constexpr char asn1_value[] =
              R"({ name {givenName "John",initial "P",familyName "Smith"},
                  title "Director",
                  number 51,
                  dateOfHire "19710917",
                  nameOfSpouse {givenName "Mary",initial "T",familyName "Smith"},
                  children
                      {
                          {name {givenName "Ralph",initial "T",familyName "Smith"},
                                  dateOfBirth "19571111"
                          },
                          {name {givenName "Susan",initial "B",familyName "Jones"},
                                  dateOfBirth "19590717"
                          }
                      }
                  })";

    c. so ...

     draft

          asn1 notation;
          constexpr char input[] = R"a(
                  PersonnelRecord ::= [APPLICATION 0] IMPLICIT SET {
                  ... skip long lines ...
              })a";
          notation.add_rule(definition);
          notation.load(input);

          generate ASN.1 structure objects
              auto node_personal = new asn1_set("PersonnelRecord", new asn1_set("PersonnelRecord", new asn1_tagged(asn1_class_application, 0, asn1_implicit));
              ... skip long code lines ...

```

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
