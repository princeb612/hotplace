/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   parser_sdk.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 *
 * Revision History
 * Date         Name                Description
 *
 */

#include <hotplace/sdk/base/stream/basic_stream.hpp>
#include <hotplace/sdk/base/system/trace.hpp>
#include <hotplace/sdk/io/parser/cfg_grammar.hpp>
#include <hotplace/sdk/io/parser/parser_sdk.hpp>
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
        for (const auto& rule : rules) {
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
        for (const auto& rule : rules) {
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
            const auto& rule = rules[item.production_id];
            if (item.dot_pos < rule.rhs.size()) {
                std::string B = rule.rhs[item.dot_pos];
                if (grammar.is_non_terminal(B)) {
                    for (const auto& r : rules) {
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
    const auto& rules = grammar.get_productions();
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
            const auto& rule = rules[item.production_id];
            if (item.dot_pos < rule.rhs.size()) {
                symbols.insert(rule.rhs[item.dot_pos]);
            }
        }

        for (const auto& sym : symbols) {
            std::set<LR0_item> goto_items;
            for (const auto& item : lr0_states[state_id]) {
                const auto& rule = rules[item.production_id];
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
                    const auto& rule = rules[item.production_id];
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

                            for (const auto& r : rules) {
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
                const auto& rule = rules[item.production_id];
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
    auto format_action = [&](const parser_action& act) -> std::string {
        if (act.type == parser_action_t::shift) {
            return "Shift(" + std::to_string(act.target) + ")";
        } else if (act.type == parser_action_t::reduce) {
            const auto& r = rules[act.target];
            return "Reduce(" + std::to_string(act.target) + ": " + r.lhs + ")";
        } else if (act.type == parser_action_t::accept) {
            return "Accept";
        }
        return "Error";
    };
#endif

    for (size_t i = 0; i < lalr_states.size(); ++i) {
        for (const auto& item : lalr_states[i]) {
            const auto& rule = rules[item.production_id];

            if (item.dot_pos < rule.rhs.size()) {
                std::string sym = rule.rhs[item.dot_pos];
                if (terminals.count(sym)) {
                    uint32 next_st = lr0_goto[{static_cast<uint32>(i), sym}];
                    auto key = std::make_pair(static_cast<uint32>(i), sym);
                    parser_action new_act = {parser_action_t::shift, next_st};

                    if (action_table.count(key)) {
                        parser_action old_act = action_table[key];
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
                    parser_action new_act = {parser_action_t::reduce, item.production_id};

                    if (action_table.count(key)) {
                        parser_action old_act = action_table[key];
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
                    const auto& rule = rules[item.production_id];
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

                            for (const auto& r : rules) {
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
                const auto& rule = rules[item.production_id];
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
            const auto& rule = rules[item.production_id];

            if (item.dot_pos < rule.rhs.size()) {
                std::string sym = rule.rhs[item.dot_pos];
                if (terminals.count(sym)) {
                    uint32 next_st = lr0_goto[{static_cast<uint32>(i), sym}];
                    auto key = std::make_pair(static_cast<uint32>(i), sym);
                    parser_action new_act = {parser_action_t::shift, next_st};

                    action_table.insert({key, new_act});
                }
            } else {
                if (0 == item.production_id) {
                    action_table.insert({{static_cast<uint32>(i), "$"}, {parser_action_t::accept, 0}});
                } else {
                    auto key = std::make_pair(static_cast<uint32>(i), item.lookahead);
                    parser_action new_act = {parser_action_t::reduce, item.production_id};

                    action_table.insert({key, new_act});
                }
            }
        }
    }

    return true;
}

}  // namespace io
}  // namespace hotplace
