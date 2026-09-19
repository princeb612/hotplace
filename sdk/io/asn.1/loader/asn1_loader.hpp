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
 * sketch
 *
 *   context-aware parser switching pattern
 *   - conceptual
 *     even GPT couldn't come up with a solution for grammar that fell outside a certain scope.
 *     so, I decided to try an approach where multiple parsers are switched under the control of a lexer.
 *   - structural
 *     the lexer delegates processing to the outer parser until it encounters BEGIN,
 *     at which point it hands over processing to the inner parser; upon encountering END,
 *     it returns control to the outer parser to finalize the process.
 *   - by first reducing the token stream using an $O(n)$ aho-corasick reducer—thereby avoiding the high cost of
 *     call-stack backup and restoration within the LALR parser—parser branching becomes significantly clearer.
 *
 * concept flow sketch
 *
 * ```
 * -- example
 * CommonDefinitions DEFINITIONS AUTOMATIC TAGS ::=
 * BEGIN
 *     AlgorithmIdentifier ::= SEQUENCE {
 *         algorithm   OBJECT IDENTIFIER,
 *         parameters  ANY OPTIONAL
 *     }
 * END
 * ```
 *
 * ````
 * lexer -> std::vector<parser_token*> -> switch module by aho-corasick reducer
 *                                                     │
 *                                                     │ switch
 *                                                     │
 *                                 ┌───────────────────┼────────────────────────────────┐
 *                                 ▼                   ▼                                ▼
 *                 1) module definition             2) ASN.1 notation               3)  OID
 *                   -> LALR Module parser           -> LALR notation parser          -> OID parser
 *
 *
 *     return_t asn1_parser::parse(asn1_runtime* runtime, const char* notation, parse_tree* pt = nullptr) const;
 *                                          |
 *         1) asn1_runtime_context::get_instance()->set("CommonDefinitions") // make asn1_runtime for "CommonDefinitions"
 *            asn1_runtime_context::get_instance()->current() -> point asn1_runtime of "CommonDefinitions"
 *
 *         2) asn1_runtime_context::get_instance()->current()->read("AlgorithmIdentifier ...  parameters  ANY OPTIONAL");
 *             generate asn1_referenced_type::define(AlgorithmIdentifier, new asn1_sequence( .... ));
 *
 * ```
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
