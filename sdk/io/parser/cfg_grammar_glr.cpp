/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   cfg_grammar_glr.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 *
 * Revision History
 * Date         Name                Description
 *
 */

#include <hotplace/sdk/base/stream/basic_stream.hpp>
#include <hotplace/sdk/base/system/trace.hpp>
#include <hotplace/sdk/io/parser/cfg_grammar.hpp>
#include <hotplace/sdk/io/parser/types.hpp>
#include <queue>

namespace hotplace {
namespace io {

bool generate_glr_tables(const cfg_grammar& grammar, parser_temporary_context_t& context, const parser_goto_table_t& goto_table,
                         parser_glr_action_table_t& action_table) {
    const auto& rules = grammar.get_productions();
    const auto& terminals = grammar.get_terminals();
    auto& first_sets = context.first_sets;
    const auto& lr0_states = context.lr0_states;
    auto& lr0_goto = context.lr0_goto;

    std::vector<std::set<LR1_item>> lalr_states(lr0_states.size());
    action_table.clear();
    lalr_states[0].insert({0, 0, "$"});

    bool changed = true;
    while (changed) {
        changed = false;
        for (size_t i = 0; i < lr0_states.size(); ++i) {
            std::set<LR1_item> expanded = lalr_states[i];
            bool closure_changed = true;

            while (closure_changed) {
                closure_changed = false;
                std::set<LR1_item> next_expanded = expanded;

                for (const auto& item : expanded) {
                    const auto& rule = grammar.get_production(item.production_id);
                    if (item.dot_pos < rule.rhs.size()) {
                        std::string B = rule.rhs[item.dot_pos];
                        if (grammar.is_non_terminal(B)) {
                            std::set<std::string> lookaheads;
                            if (item.dot_pos + 1 < rule.rhs.size()) {
                                std::string beta = rule.rhs[item.dot_pos + 1];
                                lookaheads = first_sets[beta];
                            } else {
                                lookaheads.insert(item.lookahead);
                            }

                            for (const auto& production : rules) {
                                const auto& r = production.second;
                                if (r.lhs == B) {
                                    for (const auto& la : lookaheads) {
                                        if (next_expanded.insert({r.id, 0, la}).second) {
                                            closure_changed = true;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                expanded = next_expanded;
            }
            lalr_states[i] = expanded;

            for (const auto& item : lalr_states[i]) {
                const auto& rule = grammar.get_production(item.production_id);
                if (item.dot_pos < rule.rhs.size()) {
                    std::string sym = rule.rhs[item.dot_pos];
                    uint32 next_st = lr0_goto[{static_cast<uint32>(i), sym}];
                    if (lalr_states[next_st].insert({item.production_id, item.dot_pos + 1, item.lookahead}).second) {
                        changed = true;
                    }
                }
            }
        }
    }

    // Insert actions into std::multimap without conflict rejections
    for (size_t i = 0; i < lalr_states.size(); ++i) {
        for (const auto& item : lalr_states[i]) {
            const auto& rule = grammar.get_production(item.production_id);

            if (item.dot_pos < rule.rhs.size()) {
                std::string sym = rule.rhs[item.dot_pos];
                if (terminals.count(sym)) {
                    uint32 next_st = lr0_goto[{static_cast<uint32>(i), sym}];
                    auto key = std::make_pair(static_cast<uint32>(i), sym);
                    parser_action_state new_act = {parser_action_t::shift, next_st};

                    action_table.insert({key, new_act});
                }
            } else {
                if (0 == item.production_id) {
                    action_table.insert({{static_cast<uint32>(i), "$"}, {parser_action_t::accept, 0}});
                } else {
                    auto key = std::make_pair(static_cast<uint32>(i), item.lookahead);
                    parser_action_state new_act = {parser_action_t::reduce, item.production_id};

                    action_table.insert({key, new_act});
                }
            }
        }
    }

    return true;
}

}  // namespace io
}  // namespace hotplace
