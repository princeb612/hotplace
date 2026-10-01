/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   cfg_grammar.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 * 2026-08-31   Soo Han and Gemini  study
 *
 */

#include <hotplace/sdk/base/nostd/exception.hpp>
#include <hotplace/sdk/base/nostd/utility.hpp>
#include <hotplace/sdk/base/stream/basic_stream.hpp>
#include <hotplace/sdk/base/system/trace.hpp>
#include <hotplace/sdk/io/parser/cfg_grammar.hpp>
#include <iomanip>
#include <iostream>

namespace hotplace {
namespace io {

cfg_grammar::cfg_grammar() {}

cfg_grammar& cfg_grammar::add_production(const std::string& lhs, const std::vector<std::string>& rhs) {
    uint32 id = _productions.size();  // uint32 production_id
    _productions.emplace(id, parser_production{id, lhs, rhs});
    _non_terminals.insert(lhs);

#if defined DEBUG
    if (istraceable(trace_category_t::trace_category_internal, loglevel_t::loglevel_trace)) {
        trace_debug_event(trace_category_t::trace_category_internal, trace_event_t::trace_event_internal, [&](basic_stream& dbs) -> void {
            print_style_t style("{", ", ", "}");
            style.set_element("", ", ", "");

            dbs.printf(" {%i, \"%s\", ", id, lhs.c_str());
            print(rhs, dbs, [](const std::vector<std::string>::const_iterator iter, basic_stream& dbs) -> void { dbs << "\"" << *iter << "\""; }, style);
            dbs << "},\n";
        });
    }
#endif

    return *this;
}

cfg_grammar& cfg_grammar::add_terminal(const std::string& term) {
    _terminals.insert(term);
    return *this;
}

const parser_productions_t& cfg_grammar::get_productions() const { return _productions; }

const parser_production& cfg_grammar::get_production(uint32 id) const {
    auto it = _productions.find(id);
    if (it != _productions.end()) {
        return it->second;
    } else {
        throw exception(errorcode_t::not_found);
    }
}

const parser_terminals_t& cfg_grammar::get_terminals() const { return _terminals; }

const parser_nonterminals_t& cfg_grammar::get_non_terminals() const { return _non_terminals; }

bool cfg_grammar::is_terminal(const std::string& sym) const { return _terminals.count(sym) > 0; }

bool cfg_grammar::is_non_terminal(const std::string& sym) const { return _non_terminals.count(sym) > 0; }

void cfg_grammar::clear() {
    _productions.clear();
    _terminals.clear();
    _non_terminals.clear();
}

}  // namespace io
}  // namespace hotplace
