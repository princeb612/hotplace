/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   binary_parsing_table.cpp
 * @author  Soo Han, Kim (princeb612.kr@gmail.com)
 *
 * Revision History
 * Date         Name                Description
 *
 */

#include <fstream>
#include <hotplace/sdk/io/parser/binary_parsing_table.hpp>
#include <hotplace/sdk/io/parser/cfg_grammar.hpp>

namespace hotplace {
namespace io {

binary_parsing_table::binary_parsing_table() {}

return_t binary_parsing_table::learn(parser_t* parser) {
    if (nullptr == parser) return errorcode_t::invalid_parameter;

    critical_section_guard guard(_lock);

    clear();

    auto& grammar = parser->get_cfg_grammar();
    for (const auto& pair : grammar.get_productions()) {
        const auto& production = pair.second;
        _string_index.emplace(production.lhs, 0);
        for (const auto& item : production.rhs) {
            _string_index.emplace(item, 0);
        }
    }
    for (const auto& terminal : grammar.get_terminals()) {
        _string_index.emplace(terminal, 0);
    }

    // lexicographically ascending
    uint32 idx = 0;
    for (auto& pair : _string_index) {
        pair.second = idx;
        _reverse_map.emplace(idx, pair.first);
        ++idx;
    }

    // production
    for (const auto& pair : grammar.get_productions()) {
        const auto& production = pair.second;
        buildup_production(production);
    }
    // terminal
    for (const auto& terminal : grammar.get_terminals()) {
        buildup_terminal(terminal);
    }

    // action and goto
    return parser->build(this);
}

uint32 binary_parsing_table::lookup(const std::string& symbol) {
    uint32 idx = (uint32)-1;
    critical_section_guard guard(_lock);
    auto iter = _string_index.find(symbol);
    if (_string_index.end() != iter) {
        idx = iter->second;
    }
    return idx;
}

std::string binary_parsing_table::rlookup(uint32 index) {
    std::string symbol;
    critical_section_guard guard(_lock);
    auto iter = _reverse_map.find(index);
    if (_reverse_map.end() != iter) {
        symbol = iter->second;
    }
    return symbol;
}

bool binary_parsing_table::ready() const {
    critical_section_guard guard(_lock);
    return ((false == _production_table.empty()) && (false == _action_table.empty()) && (false == _goto_table.empty()));
}

return_t binary_parsing_table::buildup_production(const parser_production& item) {
    return_t ret = errorcode_t::success;
    critical_section_guard guard(_lock);
    production_t production;
    production.id = _production_table.size();
    production.lhs = lookup(item.lhs);
    for (const auto& rhs : item.rhs) {
        auto idx = lookup(rhs);
        production.rhs.push_back(idx);
    }
    _production_table.push_back(std::move(production));
    return ret;
}

return_t binary_parsing_table::buildup_terminal(const std::string& term) {
    return_t ret = errorcode_t::success;
    critical_section_guard guard(_lock);
    auto idx = lookup(term);
    if ((uint32)-1 == idx) {
        ret = errorcode_t::bad_data;
    } else {
        _terminals.push_back(idx);
    }
    return ret;
}

return_t binary_parsing_table::buildup_action(uint32 state, const std::string& lookahead, const parser_action_state& action) {
    return_t ret = errorcode_t::success;
    critical_section_guard guard(_lock);
    bpt_action_item_t bpt;
    bpt.state = state;
    bpt.lookahead = lookup(lookahead);
    bpt.action = static_cast<uint8>(action.type);
    bpt.target = action.target;
    _action_table.push_back(std::move(bpt));
    return ret;
}
return_t binary_parsing_table::buildup_goto(uint32 state, const std::string& nonterm, uint32 next_state) {
    return_t ret = errorcode_t::success;
    critical_section_guard guard(_lock);
    bpt_goto_item_t bpt;
    bpt.state = state;
    bpt.nonterminal = lookup(nonterm);
    bpt.next_state = next_state;
    _goto_table.push_back(std::move(bpt));
    return ret;
}

void binary_parsing_table::clear() {
    critical_section_guard guard(_lock);
    _string_index.clear();
    _reverse_map.clear();
    _terminals.clear();
    _production_table.clear();
    _action_table.clear();
    _goto_table.clear();
}

}  // namespace io
}  // namespace hotplace
