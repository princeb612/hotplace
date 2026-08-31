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
#include <map>
#include <set>
#include <stack>
#include <vector>

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

enum class parser_action_t {
    shift,
    reduce,
    accept,
    error,  // conflict
};

struct parser_action {
    parser_action_t type;
    int target;  // next state on shift, rule id on reduce

    parser_action(parser_action_t a = parser_action_t::error, int t = -1) : type(a), target(t) {}
};

struct parser_production {
    int id;
    std::string lhs;
    std::vector<std::string> rhs;
};

struct LR0_item {
    int prod_id;
    size_t dot_pos;

    bool operator<(const LR0_item& other) const {
        if (prod_id != other.prod_id) return prod_id < other.prod_id;
        return dot_pos < other.dot_pos;
    }
    bool operator==(const LR0_item& other) const { return prod_id == other.prod_id && dot_pos == other.dot_pos; }
};

struct LR1_item {
    int prod_id;
    size_t dot_pos;
    std::string lookahead;

    bool operator<(const LR1_item& other) const {
        if (prod_id != other.prod_id) return prod_id < other.prod_id;
        if (dot_pos != other.dot_pos) return dot_pos < other.dot_pos;
        return lookahead < other.lookahead;
    }
};

struct parser_token {
    uint32 type;        // symbol, see token_t
    std::string value;  // lexeme
};

class cfg_grammar {
   public:
    cfg_grammar();
    cfg_grammar(const cfg_grammar& other) = default;
    cfg_grammar(cfg_grammar&& other) = default;

    cfg_grammar& operator=(const cfg_grammar& other) = default;
    cfg_grammar& operator=(cfg_grammar&& other) = default;

    cfg_grammar& add_production(const std::string& lhs, const std::vector<std::string>& rhs);
    cfg_grammar& add_terminal(const std::string& term);

    const std::vector<parser_production>& get_productions() const;
    const std::set<std::string>& get_terminals() const;
    const std::set<std::string>& get_non_terminals() const;

    bool is_terminal(const std::string& sym) const;
    bool is_non_terminal(const std::string& sym) const;

   private:
    std::vector<parser_production> _productions;
    std::set<std::string> _terminals;
    std::set<std::string> _non_terminals;
};

}  // namespace io
}  // namespace hotplace

#endif
