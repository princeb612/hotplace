/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * comments
 *
 */

#include <sdk/io/basic/parser.hpp>

namespace hotplace {
namespace io {

parser::parser() {
    get_config().set("handle_comments", 1).set("handle_quoted", 1).set("handle_token", 1);

#if 1
    // debug
    typedef std::map<uint32, std::string> debug_info;
    debug_info _token_id;  // typeof_token

    _token_id.insert({token_alpha, "alpha"});
    _token_id.insert({token_number, "number"});
    _token_id.insert({token_space, "space"});
    _token_id.insert({token_lparen, "lparen"});
    _token_id.insert({token_rparen, "rparen"});
    _token_id.insert({token_lbracket, "lbracket"});
    _token_id.insert({token_rbracket, "rbracket"});
    _token_id.insert({token_lbrace, "lbrace"});
    _token_id.insert({token_rbrace, "rbrace"});
    _token_id.insert({token_squote, "squote"});
    _token_id.insert({token_dquote, "dquote"});
    _token_id.insert({token_greater, "greater"});
    _token_id.insert({token_lesser, "lesser"});
    _token_id.insert({token_equal, "equal"});
    _token_id.insert({token_plus, "plus"});
    _token_id.insert({token_minus, "minus"});
    _token_id.insert({token_multi, "multi"});
    _token_id.insert({token_divide, "divide"});
    _token_id.insert({token_colon, "colon"});
    _token_id.insert({token_semicolon, "semiconlon"});
    _token_id.insert({token_comma, "comma"});
    _token_id.insert({token_dot, "dot"});
    _token_id.insert({token_newline, "newline"});
    _token_id.insert({token_and, "and"});
    _token_id.insert({token_or, "or"});
    _token_id.insert({token_identifier, "identifier"});
    _token_id.insert({token_quot_string, "quot_string"});
    _token_id.insert({token_comments, "comments"});
    _token_id.insert({token_assign, "assign"});
    _token_id.insert({token_lvalue, "lvalue"});
    _token_id.insert({token_emphasis, "emphasis"});

#endif
}

return_t parser::parse(parser::context& context, const char* p, size_t size) { return context.parse(this, p, size); }

parser::search_result parser::csearch(const parser::context& context, const char* pattern, size_t size_pattern, unsigned int pos) {
    return context.csearch(this, pattern, size_pattern, pos);  // handle by characters
}

parser::search_result parser::csearch(const parser::context& context, const std::string& pattern, unsigned int pos) {
    return csearch(context, pattern.c_str(), pattern.size(), pos);  // handle by characters
}

parser::search_result parser::wsearch(const parser::context& context, const char* pattern, size_t size_pattern, unsigned int pos) {
    parser::context pattern_context;
    parse(pattern_context, pattern, size_pattern);  // handle by word not characters
    return context.wsearch(this, pattern_context, pos);
}

parser::search_result parser::wsearch(const parser::context& context, const std::string& pattern, unsigned int pos) {
    return wsearch(context, pattern.c_str(), pattern.size(), pos);  // handle by word not characters
}

bool parser::compare(parser* obj, const char* lhs, const char* rhs) {
    bool ret = false;
    if (obj && lhs && rhs) {
        ret = obj->compare(lhs, rhs);
    }
    return ret;
}

bool parser::compare(const char* lhs, const char* rhs) {
    bool ret = false;
    if (lhs && rhs) {
        parser::context context_lhs;
        parser::context context_rhs;
        parse(context_lhs, lhs, strlen(lhs));
        parse(context_rhs, rhs, strlen(rhs));
        ret = compare(context_lhs, context_rhs);
    }
    return ret;
}

bool parser::compare(const parser::context& lhs, const parser::context& rhs) { return lhs.compare(this, rhs); }

parser& parser::add_token(const std::string token_name, int attr) {
    if (false == token_name.empty()) {
        _tokens.insert({token_name[0], {token_name, attr}});
    }
    return *this;
}

t_key_value<std::string, uint16>& parser::get_config() { return _keyvalue; }

std::string parser::typeof_token(uint32 type) {
    std::string id;
    auto iter = _token_id.find(type);
    if (_token_id.end() != iter) {
        id = iter->second;
    }
    return id;
}

bool parser::lookup(const std::string& word, int& idx) {
    size_t entry_no = _dictionary.index.size() + 1;  // entry 0 reserved
    auto pib = _dictionary.index.insert({word, entry_no});
    if (pib.second) {
        idx = entry_no;
        _dictionary.rindex.insert({entry_no, word});
    } else {
        idx = pib.first->second;
    }
    return true;
}

bool parser::lookup(int index, std::string& word) {
    bool ret = false;
    auto iter = _dictionary.rindex.find(index);
    if (_dictionary.rindex.end() == iter) {
        ret = false;
    } else {
        word = iter->second;
    }
    return ret;
}

bool parser::token_match(const char* p, std::string& token_name, int& token_type) {
    bool ret = false;
    __try2 {
        if (nullptr == p) {
            __leave2;
        }

        char c = *p;

        tokens_t::iterator lbound = _tokens.lower_bound(c);
        if (_tokens.end() == lbound) {
            __leave2;
        }
        tokens_t::iterator ubound = _tokens.upper_bound(c);

        for (auto iter = lbound; iter != ubound; iter++) {
            const std::string& item = iter->second.first;

            if (0 == strncmp(p, item.c_str(), item.size())) {
                token_name = item;
                token_type = iter->second.second;
                ret = true;
                break;
            }
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

void parser::dump(const parser::context& context, basic_stream& bs) {
    int line = 1;
    std::map<int, std::string> color;
    color.insert({token_lvalue, "1;34"});
    color.insert({token_assign, "1;33"});
    color.insert({token_or, "1;32"});
    color.insert({token_identifier, "1;37"});
    color.insert({token_comments, "0;37"});
    color.insert({token_emphasis, "1;35"});

    auto dump_handler = [&](const token_description* desc) -> void {
        if (line != desc->line) {
            bs.printf("\n");
            line = desc->line;
        }
        std::string code = "0;37";
        auto iter = color.find(desc->type);
        if (color.end() != iter) {
            code = iter->second;
        }
        bs.printf("\e[%sm%.*s\e[0m ", code.c_str(), (unsigned)desc->size, desc->p);
    };

    context.for_each(dump_handler);
    bs.printf("\n");
}

}  // namespace io
}  // namespace hotplace
