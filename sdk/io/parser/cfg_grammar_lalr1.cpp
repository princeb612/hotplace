/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   cfg_grammar_lalr1.cpp
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

bool generate_lalr1_tables(const cfg_grammar& grammar, parser_temporary_context_t& context, const parser_goto_table_t& goto_table,
                           parser_lalr1_action_table_t& action_table) {
    const auto& rules = grammar.get_productions();
    const auto& terminals = grammar.get_terminals();
    auto& first_sets = context.first_sets;
    const auto& lr0_states = context.lr0_states;
    auto& lr0_goto = context.lr0_goto;
    bool has_conflict = false;
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

#if defined DEBUG
    // Helper lambda for debug printing actions
    auto format_action = [&](const parser_action_state& act) -> std::string {
        if (act.type == parser_action_t::shift) {
            return "Shift(" + std::to_string(act.target) + ")";
        } else if (act.type == parser_action_t::reduce) {
            const auto& r = grammar.get_production(act.target);
            return "Reduce(" + std::to_string(act.target) + ": " + r.lhs + ")";
        } else if (act.type == parser_action_t::accept) {
            return "Accept";
        }
        return "Error";
    };
#endif

    for (size_t i = 0; i < lalr_states.size(); ++i) {
        for (const auto& item : lalr_states[i]) {
            const auto& rule = grammar.get_production(item.production_id);

            if (item.dot_pos < rule.rhs.size()) {
                std::string sym = rule.rhs[item.dot_pos];
                if (terminals.count(sym)) {
                    uint32 next_st = lr0_goto[{static_cast<uint32>(i), sym}];
                    auto key = std::make_pair(static_cast<uint32>(i), sym);
                    parser_action_state new_act = {parser_action_t::shift, next_st};

                    if (action_table.count(key)) {
                        parser_action_state old_act = action_table[key];
                        if (old_act.type != new_act.type || old_act.target != new_act.target) {
#if defined DEBUG
                            if (istraceable(trace_category_t::trace_category_internal, loglevel_t::loglevel_trace)) {
                                trace_debug_event(trace_category_t::trace_category_internal, trace_event_t::trace_event_internal, [&](basic_stream& dbs) -> void {
                                    dbs << "[CONFLICT DETECTED] state " << i << " on symbol '" << sym << "': " << format_action(old_act) << " vs "
                                        << format_action(new_act) << "\n";
                                });
                            }
#endif

                            has_conflict = true;
                        }
                    } else {
                        action_table[key] = new_act;
                    }
                }
            } else {
                if (item.production_id == 0) {
                    action_table[{static_cast<uint32>(i), "$"}] = {parser_action_t::accept, 0};
                } else {
                    auto key = std::make_pair(static_cast<uint32>(i), item.lookahead);
                    parser_action_state new_act = {parser_action_t::reduce, item.production_id};

                    if (action_table.count(key)) {
                        parser_action_state old_act = action_table[key];
                        if (old_act.type != new_act.type || old_act.target != new_act.target) {
#if defined DEBUG
                            if (istraceable(trace_category_t::trace_category_internal, loglevel_t::loglevel_trace)) {
                                trace_debug_event(trace_category_t::trace_category_internal, trace_event_t::trace_event_internal, [&](basic_stream& dbs) -> void {
                                    dbs << "[CONFLICT DETECTED] state " << i << " on lookahead '" << item.lookahead << "': " << format_action(old_act) << " vs "
                                        << format_action(new_act) << "\n";
                                    dbs << "  - attempted rule: " << rule.id << " -> " << rule.lhs << "\n";
                                });
                            }
#endif
                            has_conflict = true;
                        }
                    } else {
                        action_table[key] = new_act;
                    }
                }
            }
        }
    }

    return (false == has_conflict);
}

}  // namespace io
}  // namespace hotplace
