/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   lalr_parser.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 * 2026-08-29   Soo Han and Gemini  study
 *
 */

#ifndef __HOTPLACE_SDK_IO_PARSER_LALRPARSER__
#define __HOTPLACE_SDK_IO_PARSER_LALRPARSER__

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
class lalr_parser {
   public:
    lalr_parser() = default;
    explicit lalr_parser(const cfg_grammar& g);
    explicit lalr_parser(cfg_grammar&& g);

    void set_grammar(const cfg_grammar& g);
    void set_grammar(cfg_grammar&& g);

    const cfg_grammar& get_cfg_grammar() const;

    /**
     * LALR(1) dynamic table creation
     */
    return_t build_table();

    /**
     * perform dynamically generated table-based parsing
     * @param const std::vector<parser_token>& tokens [in]
     * @param parse_tree* pt [outopt] generate parse tree if necessary
     */
    return_t parse(const std::vector<parser_token>& tokens, parse_tree* pt = nullptr);

   protected:
    void compute_first_and_follow_sets();
    std::set<LR0_item> closure_lr0(std::set<LR0_item> items) const;
    void build_lr0_states();
    bool generate_lalr_tables();

   private:
    cfg_grammar _grammar;
    bool _is_table_built = false;

    // temporary tables for table generation
    std::map<std::string, std::set<std::string>> _first_sets;
    std::map<std::string, std::set<std::string>> _follow_sets;
    std::vector<std::set<LR0_item>> _lr0_states;
    std::map<std::pair<int, std::string>, int> _lr0_goto;

    // essential LALR parsing tables
    std::map<std::pair<int, std::string>, parser_action> _action_table;
    std::map<std::pair<int, std::string>, int> _goto_table;
};

}  // namespace io
}  // namespace hotplace

#endif
