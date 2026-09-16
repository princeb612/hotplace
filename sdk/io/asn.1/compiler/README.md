### ASN.1 Compiler (asn1c) Flow - Gemini

#### 1. Output Artifacts and Build Structure
The asn1c compiler takes a .asn1 schema file as input and generates C++11-based data models, encoder/decoder source code, and build scripts.

- A. Generated File Composition
  - user_profile.hpp: Declarations for data structures (struct), enumerations (enum class), codec interface methods, and validation functions.
  - user_profile.cpp: Implementation of codecs integrated with `hotplace::io::basic_stream` and constraint validation logic.
  - Makefile: A script that combines the generated source code and the test driver's main function to produce an executable file (`userprofile_test`).
- B. Makefile Integration Example
  ```
  ASN1C = ./bin/asn1c
  ASN1_SRCS = UserProfile.asn1
  GEN_HDRS = generated/user_profile.hpp
  GEN_SRCS = generated/user_profile.cpp

  all: $(GEN_HDRS) $(GEN_SRCS)

  $(GEN_HDRS) $(GEN_SRCS): $(ASN1_SRCS)
      @mkdir -p generated
      $(ASN1C) -o generated/ --hpp-ext .hpp --cpp-ext .cpp $(ASN1_SRCS)
  ```
- C. Cross-Platform Support Specifications
  - Build System: In addition to the standard Makefile, provides `CMakeLists.txt` or flags compatible with `nmake` for Windows Visual Studio environments.
  - Platform Preprocessor:
    ```
    #if defined(_MSC_VER)
        // MSVC-specific macros and type definitions
    #elif defined(__MINGW32__) || defined(__GNUC__)
        // GCC / MinGW64-related definitions
    #endif
    ```

#### 2. CLI Utility (asn1c) Command Option Design

- A. Basic Execution Format
  ```
  Bash
  asn1c [options] <asn1_file_1> [<asn1_file_2> ...]
  ```
- B. CLI Option Specification
  | Option | Short Name | Description | Remarks |
  | -- | -- | -- | -- |
  | --output-dir <dir> | -o | Output directory for generated source code | Default: ./ |
  | --namespace <ns> | -n | Name of the generated C++ namespace | E.g., generated |
  | --codec <type> | -c | Default codec type (der only) | Default: der |
  | --enable-constraint | | Enable/disable generation of constraint check code (SIZE, RANGE, etc.) | Default: Enabled |
  | --verbose | -v | Output detailed logs for parsing AST and generation | For debugging |
  | --help | -h | Display command help | |

#### 3. Implementation Scope and C++ Type Mapping Specification

- Supports the DER (Distinguished Encoding Rules) method and maps the `asn1_tag_t` tag types defined in the table below to C++11 structures.
- A. Supported asn1_tag_t Types
  | ASN.1 Tag Enum (enum asn1_tag_t) | ASN.1 Syntax | C++11 Mapping Structure | Remarks |
  | -- | -- | -- | -- |
  | asn1_tag_boolean (1) | BOOLEAN | bool |
  | asn1_tag_integer (2) | INTEGER | int32_t, uint32_t, int64_t | Reflects range constraints |
  | asn1_tag_bitstring (3) | BIT STRING | std::vector<uint8_t> | Bit flags |
  | asn1_tag_octstring (4) | OCTET STRING | std::vector<uint8_t> | Byte array |
  | asn1_tag_null (5) | NULL | std::monostate / bool | No state |
  | asn1_tag_objid (6) | OBJECT IDENTIFIER | std::string | OID dot notation (e.g., "1.2.840...") |
  | asn1_tag_real (9) | REAL | double |
  | asn1_tag_enum (10) | ENUMERATED | enum class |
  | asn1_tag_utf8string (12) | UTF8String | std::string | UTF-8 string |
  | asn1_tag_relobjid (13) | RELATIVE-OID | std::string |
  | asn1_tag_time (14) | TIME | std::string |
  | asn1_tag_sequence (16) | SEQUENCE, SEQUENCE OF | struct / std::vector<T> | Includes `has_field` if OPTIONAL |
  | asn1_tag_set (17) | SET, SET OF | struct / std::vector<T> | Handles DER tag order sorting |
  | asn1_tag_ia5string (22) | IA5String | std::string | ASCII string |
  | asn1_tag_utctime (23) | UTCTime | std::string / time_t |
  | asn1_tag_generalizedtime (24) | GeneralizedTime | std::string / time_t |
  | asn1_tag_numstring (18) ~ asn1_tag_duration (34) | Other String/Time types | String mapping following std::string rules |

> Excluded types: ObjectDescriptor (7), EXTERNAL (8), and EMBEDDED PDV (11) are not supported.

- B. Module Tagging Options (Tagging Environment)
  | Tag Option | Description and Handling |
  | -- | -- |
  | AUTOMATIC TAGS | Automatically assigns Context-specific Tags ([0], [1]...) based on field order; processed internally as IMPLICIT. |
  | IMPLICIT TAGS | Applies IMPLICIT by default even if the keyword is omitted when assigning tags (replaces the original TLV tag to reduce encoding size). |
  | EXPLICIT TAGS | Applies EXPLICIT by default if the keyword is omitted (wraps the original type in a TLV structure). |

#### 4. Output Verification Scenario (Test Driver)

- A. Test Execution Flow (CLI)
  ```bash
  # 1. Read JSON configuration file and serialize to DER binary
  ./userprofile_test -encode_der -in input.json -out outfile.der

  # 2. Read DER binary, deserialize into C++ object, and dump as text
  ./userprofile_test -decode -in outfile.der
  ```

- B. Example Input File Structure (input.json)
  ```json
  {
      "id": 1004,
      "username": "john_doe",
      "isActive": true,
      "role": "admin",
      "aliases": ["johny", "jd"],
      "contact": {
          "type": "email",
          "value": "john@example.com"
      }
  }
  ```
- C. Example Decode Output (Tree Dump)
  ```text
  [+] Successfully decoded (Total 48 bytes read)
  [+] Constraint Validation: PASSED

  -- UserProfile Object Dump --
  UserProfile {
      id: 1004
      username: "john_doe"
      isActive: true
      role: admin (0)
      aliases: [ (2 items)
          [0]: "johny"
          [1]: "jd"
      ]
      contact: CHOICE (email) {
          email: "john@example.com"
      }
  }
  ```

#### 5. C++ Code Structuring Model (Based on UserProfile.asn1)

- A. Schema Definition (UserProfile.asn1)
  ```
  UserProfile-Module DEFINITIONS AUTOMATIC TAGS ::=
  BEGIN

  -- 1. Main structure containing user information
  UserProfile ::= SEQUENCE {
      id          INTEGER (1..4294967295),        -- ID starting from 1 (range-limited)
      username    IA5String (SIZE(3..20)),        -- Username (3 to 20 characters)
      isActive    BOOLEAN,                        -- Activation status
      role        UserRole,                       -- Uses the enumerated type defined below
      aliases     SEQUENCE OF IA5String OPTIONAL, -- List of aliases (optional)
      contact     ContactInfo                     -- Contact information (CHOICE type)
  }

  -- 2. ENUMERATED definition
  UserRole ::= ENUMERATED {
      admin(0),
      user(1),
      guest(2)
  }

  -- 3. CHOICE type definition (select either email or phone number)
  ContactInfo ::= CHOICE {
      email       IA5String,
      phoneNumber IA5String
  }

  END
  ```

- B. Header File Sketch (user_profile.hpp)
  ```
  #pragma once

  #include <string>
  #include <vector>
  #include <hotplace/sdk/io/asn.1/asn1_object.hpp>

  namespace generated {
      // ENUMERATED Mapping
      enum class UserRole {
          admin = 0,
          user = 1,
          guest = 2
      };

      // CHOICE Mapping
      struct ContactInfo {
          enum class ChoiceType {
          unspecified = 0,
          email,
          phoneNumber
      };

      ChoiceType type = ChoiceType::unspecified;
      std::string email;
      std::string phoneNumber;

      ContactInfo() = default;
  };

  // SEQUENCE Mapping
  struct UserProfile {
      uint32_t id = 0; // INTEGER (1..4294967295)
      std::string username; // IA5String (SIZE(3..20))
      bool isActive = false; // BOOLEAN
      UserRole role = UserRole::user; // ENUMERATED
      std::vector<std::string> aliases; // SEQUENCE OF IA5String (OPTIONAL)
      bool has_aliases = false; // Flag for OPTIONAL field presence
      ContactInfo contact; // CHOICE

      // Codec & Validation Interface
      int encode(hotplace::io::basic_stream* stream) const;
      int decode(const uint8_t* buffer, size_t size);
      bool check_constraints() const;
  };

  } // namespace generated
  ```
- C. Source File Implementation (user_profile.cpp)
  - Constraint Checking: Range checks for 1 <= id <= 4294967295 and 3 <= username.length() <= 20
  - Error Handling: C++11 standard practices and safe cleanup handling
