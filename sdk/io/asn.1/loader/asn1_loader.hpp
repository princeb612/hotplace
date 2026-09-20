/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_loader.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 * 2026.09.18   Soo Han and Gemini  context-aware parser switching pattern
 *
 * reasons for context-aware switching
 *   S' -> Statement
 *   S' -> ModuleDefinition -> AssignmentList -> Statement
 *
 *   If these two paths coexist in a single LALR parsing table, their lookahead sets
 *   overlap during the calculation of the state closure, making a conflict unavoidable.
 *   The essence is that the parsing path cannot be disambiguated using only a single
 *   lookahead token (LALR(1)).
 *
 * sketch
 *   context-aware parser switching pattern
 *   - conceptual
 *     When designing a higher-level grammar that encompasses both 'ModuleDefinition' and 'Statement'
 *     contexts, conflicts inevitably arise for the reasons explained above.
 *     To resolve this, multiple parsers are dynamically switched under the control of the lexer.
 *   - structural
 *     The lexer delegates processing to the outer parser (Module Parser) until it encounters
 *     BEGIN, at which point it hands over control to the inner parser (Notation Parser).
 *     Upon encountering END, control returns to the outer parser to finalize the module.
 *   - optimization
 *     By pre-reducing the token stream using an O(n) Aho-Corasick reducer—thereby avoiding
 *     the high cost of call-stack backup and restoration within the LALR parser—parser
 *     branching becomes significantly clearer and more deterministic.
 *
 * concept flow sketch
 *
 * ```
 * -- example
 * CommonDefinitions DEFINITIONS AUTOMATIC TAGS ::=
 * BEGIN
 *     AlgorithmIdentifier ::= SEQUENCE {
 *         algorithm    OBJECT IDENTIFIER,
 *         parameters   ANY OPTIONAL
 *     }
 * END
 * ```
 *
 * ````
 * lexer -> std::vector<parser_token*> -> switch module by aho-corasick reducer
 *                                                          │
 *                                                          │ switch
 *                                                          │
 *                  ┌───────────────────────────────────────┼───────────────────────────────────────┐
 *                  ▼                                       ▼                                       ▼
 *       1) module definition                    2) ASN.1 notation                           3) OID
 *        -> LALR Module parser                   -> LALR notation parser                     -> OID parser
 *
 *
 *       return_t asn1_parser::parse(asn1_runtime* runtime, const char* notation, parse_tree* pt = nullptr) const;
 *                                                  │
 *           1) asn1_runtime_context::get_instance()->set("CommonDefinitions"); // instantiate asn1_runtime for "CommonDefinitions"
 *              asn1_runtime_context::get_instance()->current();                // set current pointer to "CommonDefinitions" runtime
 *
 *           2) asn1_runtime_context::get_instance()->current()->read("AlgorithmIdentifier ... parameters ANY OPTIONAL");
 *              // register symbol: asn1_referenced_type::define(AlgorithmIdentifier, new asn1_sequence( .... ));
 * ````
 *
 */

#ifndef __HOTPLACE_SDK_IO_ASN1_LOADER_ASN1LOADER__
#define __HOTPLACE_SDK_IO_ASN1_LOADER_ASN1LOADER__

#include <hotplace/sdk/io/asn.1/basic/types.hpp>
#include <hotplace/sdk/io/asn.1/runtime/types.hpp>

namespace hotplace {
namespace io {

class asn1_loader {
   public:
    asn1_loader();
    ~asn1_loader();

    /**
     * @examples
     *          // sketch
     *          auto rtcontext = asn1_runtime_context::get_instance();
     *          loader.load_file("userprofile.asn1", name);
     *          rtcontext->select(name);
     */
    static return_t load_file(const char* asn1file, std::string& name);
    /**
     * @examples
     *          // sketch
     *          auto rtcontext = asn1_runtime_context::get_instance();
     *          loader.load_file(asn1stream, asn1size, name);
     *          rtcontext->select(name);
     */
    static return_t load(const char* asn1, size_t size, std::string& name);
};

}  // namespace io
}  // namespace hotplace

#endif
