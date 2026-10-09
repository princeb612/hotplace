/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   lalr1_parser.hpp
 * @author  Soo Han, Kim (princeb612.kr@gmail.com)
 *
 * Revision History
 * Date         Name                Description
 * 2026.08.29   Soo Han and Gemini  study
 *
 * LALR(1) dynamic table creation vs. importing pre-built tables
 *
 *   ASN.1 production (measured based on approximately 130 productions.)
 *          |time       |message
 *   learn  |0.444620100|build parsing table
 *   import |0.032957500|import parsing table
 *
 * S' -> Statement
 * S' -> ModuleDefinition -> AssignmentList -> Statement
 *
 * If these two paths coexist in a single LALR parsing table, their lookahead sets overlap during the calculation of the state closure, making a conflict unavoidable.
 *
 */

#ifndef __HOTPLACE_SDK_IO_PARSER_LALR1PARSER__
#define __HOTPLACE_SDK_IO_PARSER_LALR1PARSER__

#include <hotplace/sdk/base/system/critical_section.hpp>
#include <hotplace/sdk/base/system/shared_instance.hpp>
#include <hotplace/sdk/io/parser/cfg_grammar.hpp>
#include <hotplace/sdk/io/parser/parse_tree.hpp>

namespace hotplace {
namespace io {

/**
 * @brief LALR parser
 * @remarks
 *          state = stack.top();
 *          token = lookahead;
 *
 *          action = ACTION[state][token];
 *
 *          switch (action.type) {
 *              case SHIFT:
 *                  push(token);
 *                  state = action.state;
 *                  read_next_token();
 *                  break;
 *
 *              case REDUCE:
 *                  pop(rhs_size);
 *                  lhs = rule.lhs;
 *                  state = GOTO[stack.top()][lhs];
 *                  push(lhs);
 *                  break;
 *
 *              case ACCEPT:
 *                  return success;
 *
 *              case ERROR:
 *                  return error;
 *          }
 */
class lalr1_parser : public parser_t {
   public:
    lalr1_parser();
    explicit lalr1_parser(const cfg_grammar& g);
    explicit lalr1_parser(cfg_grammar&& g);

    virtual void set_grammar(const cfg_grammar& g);
    virtual void set_grammar(cfg_grammar&& g);

    virtual const cfg_grammar& get_cfg_grammar() const;
    virtual cfg_grammar& get_cfg_grammar();

    /**
     * @brief   load productions, terminals and generate string table
     * @examples
     *          // build dynamically
     *          cfg_grammar grammar;
     *          grammar.add_production(...);
     *          grammar.add_terminal(...);
     *          lalr1_parser lalr(std::move(grammar));
     *          lalr.build();  // action and goto table
     */
    virtual return_t learn();

    virtual bool ready() const;
    virtual void clear();

    /**
     * @remarks perform dynamically generated table-based parsing
     * @param   const std::vector<parser_token>& tokens [in]
     * @param   parse_tree* pt [outopt] generate parse tree if necessary
     */
    virtual return_t parse(const std::vector<parser_token>& tokens, parse_tree* pt = nullptr);
    /**
     * @brief   action and goto table
     * @param   binary_parsing_table* table [in]
     */
    virtual return_t build(binary_parsing_table* table);

    virtual parser_type_t get_type() const;

    virtual bool imported() const;
    virtual void addref();
    virtual void release();

   protected:
    // import
    virtual return_t buildup_action(uint32 state, const std::string& lookahead, parser_action_state action);
    virtual return_t buildup_goto(uint32 state, const std::string& nonterm, uint32 next_state);
    virtual void import_completed();

   private:
    t_shared_reference<lalr1_parser> _shared;
    mutable critical_section _lock;
    cfg_grammar _grammar;
    bool _is_table_built{false};
    bool _is_imported{false};

    // temporary tables for table generation
    parser_temporary_context_t _context;

    // essential LALR parsing tables
    parser_lalr1_action_table_t _action_table;
    parser_goto_table_t _goto_table;
};

}  // namespace io
}  // namespace hotplace

#endif
