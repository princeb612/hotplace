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
    int id = _productions.size();
    _productions.push_back({id, lhs, rhs});
    _non_terminals.insert(lhs);
#if defined DEBUG
    if (istraceable(trace_category_t::trace_category_internal, loglevel_t::loglevel_trace)) {
        trace_debug_event(trace_category_t::trace_category_internal, trace_event_t::trace_event_internal, [&](basic_stream& dbs) -> void {
            dbs.printf("[%i] lhs:%s rhs:", id, lhs.c_str());
            print<std::vector<std::string>, basic_stream>(rhs, dbs, "{", ",", "}");
            dbs << "\n";
        });
    }
#endif
    return *this;
}

cfg_grammar& cfg_grammar::add_terminal(const std::string& term) {
    _terminals.insert(term);
    return *this;
}

const std::vector<parser_production>& cfg_grammar::get_productions() const { return _productions; }

const std::set<std::string>& cfg_grammar::get_terminals() const { return _terminals; }

const std::set<std::string>& cfg_grammar::get_non_terminals() const { return _non_terminals; }

bool cfg_grammar::is_terminal(const std::string& sym) const { return _terminals.count(sym) > 0; }

bool cfg_grammar::is_non_terminal(const std::string& sym) const { return _non_terminals.count(sym) > 0; }

}  // namespace io
}  // namespace hotplace
