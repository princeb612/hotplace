/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   cfg_grammar_rule.cpp
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

void compute_first_and_follow_sets(const cfg_grammar& grammar, parser_temporary_context_t& context) {
    const auto& rules = grammar.get_productions();
    const auto& terminals = grammar.get_terminals();
    auto& first_sets = context.first_sets;
    auto& follow_sets = context.follow_sets;

    first_sets.clear();
    follow_sets.clear();

    for (const auto& term : terminals) {
        first_sets[term].insert(term);
    }

    bool changed = true;
    while (changed) {
        changed = false;
        for (const auto& pair : rules) {
            const auto rule = pair.second;
            if (rule.rhs.empty()) continue;

            std::string first_rhs = rule.rhs[0];
            size_t prev_size = first_sets[rule.lhs].size();

            for (const auto& sym : first_sets[first_rhs]) {
                first_sets[rule.lhs].insert(sym);
            }

            if (first_sets[rule.lhs].size() > prev_size) {
                changed = true;
            }
        }
    }

    follow_sets["S'"].insert("$");
    changed = true;
    while (changed) {
        changed = false;
        for (const auto& pair : rules) {
            const auto rule = pair.second;
            for (size_t i = 0; i < rule.rhs.size(); ++i) {
                std::string B = rule.rhs[i];
                if (false == grammar.is_non_terminal(B)) continue;

                size_t prev_size = follow_sets[B].size();

                if (i + 1 < rule.rhs.size()) {
                    std::string beta = rule.rhs[i + 1];
                    for (const auto& sym : first_sets[beta]) {
                        follow_sets[B].insert(sym);
                    }
                } else {
                    for (const auto& sym : follow_sets[rule.lhs]) {
                        follow_sets[B].insert(sym);
                    }
                }

                if (follow_sets[B].size() > prev_size) {
                    changed = true;
                }
            }
        }
    }
}

std::set<LR0_item> closure_lr0(const cfg_grammar& grammar, std::set<LR0_item> items) {
    const auto& rules = grammar.get_productions();
    bool added = true;
    while (added) {
        added = false;
        std::set<LR0_item> new_items = items;
        for (const auto& item : items) {
            const auto& rule = grammar.get_production(item.production_id);
            if (item.dot_pos < rule.rhs.size()) {
                std::string B = rule.rhs[item.dot_pos];
                if (grammar.is_non_terminal(B)) {
                    for (const auto& production : rules) {
                        const auto& r = production.second;
                        if (r.lhs == B) {
                            if (new_items.insert({r.id, 0}).second) {
                                added = true;
                            }
                        }
                    }
                }
            }
        }
        items = std::move(new_items);
    }
    return items;
}

void build_lr0_states(const cfg_grammar& grammar, parser_temporary_context_t& context, parser_goto_table_t& goto_table) {
    // const auto& rules = grammar.get_productions();
    auto& lr0_states = context.lr0_states;
    auto& lr0_goto = context.lr0_goto;
    lr0_states.clear();
    lr0_goto.clear();
    goto_table.clear();

    std::set<LR0_item> start_set = closure_lr0(grammar, {{0, 0}});
    lr0_states.push_back(start_set);

    std::queue<uint32> worklist;
    worklist.push(0);

    while (false == worklist.empty()) {
        uint32 state_id = worklist.front();
        worklist.pop();

        std::set<std::string> symbols;
        for (const auto& item : lr0_states[state_id]) {
            const auto& rule = grammar.get_production(item.production_id);
            if (item.dot_pos < rule.rhs.size()) {
                symbols.insert(rule.rhs[item.dot_pos]);
            }
        }

        for (const auto& sym : symbols) {
            std::set<LR0_item> goto_items;
            for (const auto& item : lr0_states[state_id]) {
                const auto& rule = grammar.get_production(item.production_id);
                if (item.dot_pos < rule.rhs.size() && rule.rhs[item.dot_pos] == sym) {
                    goto_items.insert({item.production_id, item.dot_pos + 1});
                }
            }
            std::set<LR0_item> next_state = closure_lr0(grammar, goto_items);

            uint32 existing_state = -1;
            for (size_t i = 0; i < lr0_states.size(); ++i) {
                if (lr0_states[i] == next_state) {
                    existing_state = static_cast<uint32>(i);
                    break;
                }
            }

            if (existing_state == (uint32)-1) {
                lr0_states.push_back(next_state);
                existing_state = static_cast<uint32>(lr0_states.size() - 1);
                worklist.push(existing_state);
            }

            lr0_goto[{state_id, sym}] = existing_state;

            if (grammar.is_non_terminal(sym)) {
                goto_table[{state_id, sym}] = existing_state;
            }
        }
    }
}

}  // namespace io
}  // namespace hotplace
