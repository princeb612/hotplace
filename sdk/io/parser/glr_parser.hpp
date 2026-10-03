/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   glr_parser.hpp
 * @author  Soo Han, Kim (princeb612.kr@gmail.com)
 *
 * Revision History
 * Date         Name                Description
 * 2026.09.22   Soo Han and Gemini  study
 *
 * GLR (Generalized LR) Parser
 * Parser Type | Deterministic Grammar (Time) | Ambiguous / Worst-Case Grammar (Time) | Space Complexity
 * LALR(1)     | O(n)                         | Fails / Conflicts out                 | O(n) (stack) + label size
 * GLR         | O(n)                         | O(n^3) (general) to O(n^4)+           | O(n^p) or graph structured stack
 *
 * GLR dynamic table creation vs. importing pre-built tables
 *
 *   ASN.1 production (measured based on approximately 140 productions.)
 *          |time       |message
 *   learn  |3.003206025|build parsing table
 *   import |0.000022600|import parsing table
 *
 */

#ifndef __HOTPLACE_SDK_IO_PARSER_GLRPARSER__
#define __HOTPLACE_SDK_IO_PARSER_GLRPARSER__

#include <hotplace/sdk/base/system/critical_section.hpp>
#include <hotplace/sdk/io/parser/cfg_grammar.hpp>
#include <hotplace/sdk/io/parser/parse_tree.hpp>

namespace hotplace {
namespace io {

class glr_parser : public parser_t {
   public:
    glr_parser() = default;
    explicit glr_parser(const cfg_grammar& g);
    explicit glr_parser(cfg_grammar&& g);

    virtual void set_grammar(const cfg_grammar& g);
    virtual void set_grammar(cfg_grammar&& g);

    virtual const cfg_grammar& get_cfg_grammar() const;
    virtual cfg_grammar& get_cfg_grammar();

    /**
     * @brief build LALR/LR parsing table with multi-action conflict tolerance.
     */
    virtual return_t learn();

    virtual bool ready() const;
    virtual void clear();

    /**
     * @brief execute GLR parsing using Graph-Structured Stack (GSS).
     */
    virtual return_t parse(const std::vector<parser_token>& tokens, parse_tree* pt = nullptr);
    /**
     * @brief   action and goto table
     */
    virtual return_t build(binary_parsing_table* table);

    virtual parser_type_t get_type() const;
    virtual uint16 get_version() const;

   protected:
    // import
    virtual return_t buildup_action(uint32 state, const std::string& lookahead, parser_action_state action);
    virtual return_t buildup_goto(uint32 state, const std::string& nonterm, uint32 next_state);
    virtual void imported();

   private:
    mutable critical_section _lock;
    cfg_grammar _grammar;
    bool _is_table_built = false;

    // temporary tables for table generation
    parser_temporary_context_t _context;

    // GLR parsing tables: multi-action table allows conflicts to co-exist
    parser_glr_action_table_t _action_table;
    parser_goto_table_t _goto_table;
};

}  // namespace io
}  // namespace hotplace

#endif
