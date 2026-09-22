/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file    lalr_parser.hpp
 * @author  Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc    Context-aware parser switching architecture for complex grammars (e.g., ASN.1)
 *
 * Revision History
 * Date         Name                Description
 * 2026.08.29   Soo Han and Gemini  study
 *
 * GLR (Generalized LR) Parser
 * Parser Type | Deterministic Grammar (Time) | Ambiguous / Worst-Case Grammar (Time) | Space Complexity
 * LALR(1)     | O(n)                         | Fails / Conflicts out                 | O(n) (stack) + label size
 * GLR         | O(n)                         | O(n^3) (general) to O(n^4)+           | O(n^p) or graph structured stack
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

    const cfg_grammar& get_cfg_grammar() const;

    /**
     * @brief build LALR/LR parsing table with multi-action conflict tolerance.
     */
    virtual return_t learn();

    /**
     * @brief import prebuilt multi-action table and goto table.
     */
    return_t import(const std::vector<parser_production>& productions,                                 //
                    const std::multimap<std::pair<uint32, std::string>, parser_action>& action_table,  //
                    const std::map<std::pair<uint32, std::string>, uint32>& goto_table);

    virtual bool ready() const;

    /**
     * @brief execute GLR parsing using Graph-Structured Stack (GSS).
     */
    virtual return_t parse(const std::vector<parser_token>& tokens, parse_tree* pt = nullptr);

   protected:
    /**
     * @brief internal node for Graph-Structured Stack (GSS)
     */
    struct gss_node {
        uint32 state;
        std::shared_ptr<gss_node> parent;
        parse_treenode* tree_node;

        gss_node(uint32 s, std::shared_ptr<gss_node> p, parse_treenode* node = nullptr) : state(s), parent(p), tree_node(node) {}
    };

    void compute_first_and_follow_sets();
    std::set<LR0_item> closure_lr0(std::set<LR0_item> items) const;
    void build_lr0_states();

    /**
     * @brief generates GLR tables (allows multiple actions per state-token pair).
     */
    bool generate_glr_tables();

   private:
    mutable critical_section _lock;
    cfg_grammar _grammar;
    bool _is_table_built = false;

    // temporary tables for table generation
    std::map<std::string, std::set<std::string>> _first_sets;
    std::map<std::string, std::set<std::string>> _follow_sets;
    std::vector<std::set<LR0_item>> _lr0_states;
    std::map<std::pair<uint32, std::string>, uint32> _lr0_goto;

    // GLR parsing tables: multi-action table allows conflicts to co-exist
    std::multimap<std::pair<uint32, std::string>, parser_action> _action_table;
    std::map<std::pair<uint32, std::string>, uint32> _goto_table;
};

}  // namespace io
}  // namespace hotplace

#endif
