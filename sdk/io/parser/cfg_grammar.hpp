/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   cfg_grammar.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 * 2026-08-29   Soo Han and Gemini  study
 *
 */

#ifndef __HOTPLACE_SDK_IO_PARSER_CFGGRAMMAR__
#define __HOTPLACE_SDK_IO_PARSER_CFGGRAMMAR__

#include <hotplace/sdk/base/system/critical_section.hpp>
#include <hotplace/sdk/io/parser/types.hpp>

namespace hotplace {
namespace io {

/**
 * CFG (Context-free grammar)
 * Formal definitions
 *   A context-free grammar G is defined by the 4-tuple G=(V,Σ,R,S)
 *     V is a finite set; each element v∈V is called a nonterminal character or a variable
 *     Σ is a finite set of terminals, disjoint from V, which make up the actual content of the sentence.
 *     R The members of R are called the rules or productions of the grammar (also commonly symbolized by a P).
 *     S is the start variable (or start symbol), used to represent the whole sentence (or program). It must be an element of V.
 *  keyword : non-terminal set, terminal set, production set, start symbol
 */

class cfg_grammar {
    friend class glr_parser;
    friend class lalr1_parser;

   public:
    cfg_grammar();
    cfg_grammar(const cfg_grammar& other) = default;
    cfg_grammar(cfg_grammar&& other) = default;

    cfg_grammar& operator=(const cfg_grammar& other) = default;
    cfg_grammar& operator=(cfg_grammar&& other) = default;

    cfg_grammar& add_production(const std::string& lhs, const std::vector<std::string>& rhs);
    cfg_grammar& add_terminal(const std::string& term);

    const parser_productions_t& get_productions() const;
    const parser_production& get_production(uint32 id) const;
    uint32 get_production_id(const std::string& rule) const;
    const parser_terminals_t& get_terminals() const;
    const parser_nonterminals_t& get_non_terminals() const;

    bool is_terminal(const std::string& sym) const;
    bool is_non_terminal(const std::string& sym) const;

    void clear();

   private:
    parser_productions_t _productions;
    parser_production_lookup_t _production_lookup;
    parser_terminals_t _terminals;
    parser_nonterminals_t _non_terminals;
};

}  // namespace io
}  // namespace hotplace

#endif
