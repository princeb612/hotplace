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

#include <hotplace/sdk/io/basic/parser.hpp>

namespace hotplace {
namespace io {

parser::parser() {
    auto tokenptr_to_int = [](token* const* source, size_t index) -> int {
        const token* t = source[index];
        return t->get_type();
    };
    _ac = new t_aho_corasick<int, token*>(tokenptr_to_int);
    get_config().set("handle_comments", 1).set("handle_quoted", 1).set("handle_token", 1);

#if 1
    // debug

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
    _token_id.insert({token_word, "identifier"});
    _token_id.insert({token_quot_string, "quot_string"});
    _token_id.insert({token_comments, "comments"});
    _token_id.insert({token_assign, "assign"});
    _token_id.insert({token_lvalue, "lvalue"});
    _token_id.insert({token_emphasis, "emphasis"});
    _token_id.insert({token_type, "type"});
    _token_id.insert({token_class, "class"});
    _token_id.insert({token_tag, "tag"});
    _token_id.insert({token_bool, "bool"});
    _token_id.insert({token_int, "int"});
    _token_id.insert({token_bitstring, "bitstring"});
    _token_id.insert({token_octstring, "octstring"});
    _token_id.insert({token_null, "null"});
    _token_id.insert({token_oid, "oid"});
    _token_id.insert({token_objdesc, "objdesc"});
    _token_id.insert({token_extern, "extern"});
    _token_id.insert({token_real, "real"});
    _token_id.insert({token_enum, "enum"});
    _token_id.insert({token_embedpdv, "emdedpdv"});
    _token_id.insert({token_utf8string, "utf8string"});
    _token_id.insert({token_reloid, "reloid"});
    _token_id.insert({token_sequence, "sequence"});
    _token_id.insert({token_sequenceof, "sequenceof"});
    _token_id.insert({token_set, "set"});
    _token_id.insert({token_setof, "setof"});
    _token_id.insert({token_numstring, "numstring"});
    _token_id.insert({token_printstring, "printstring"});
    _token_id.insert({token_t61string, "t61string"});
    _token_id.insert({token_videotexstring, "videotexstring"});
    _token_id.insert({token_ia5string, "ia5string"});
    _token_id.insert({token_utctime, "utctime"});
    _token_id.insert({token_generalizedtime, "generalizedtime"});
    _token_id.insert({token_graphicstring, "graphicstring"});
    _token_id.insert({token_visiblestring, "visiblestring"});
    _token_id.insert({token_genaralstring, "generalstring"});
    _token_id.insert({token_universalstring, "universalstring"});
    _token_id.insert({token_bmpstring, "bmpstring"});
    _token_id.insert({token_date, "date"});
    _token_id.insert({token_timeofday, "timeofday"});
    _token_id.insert({token_datetime, "datetime"});
    _token_id.insert({token_duration, "duration"});
    _token_id.insert({token_true, "true"});
    _token_id.insert({token_false, "false"});
    _token_id.insert({token_universal, "universal"});
    _token_id.insert({token_application, "application"});
    _token_id.insert({token_private, "private"});
    _token_id.insert({token_implicit, "implicit"});
    _token_id.insert({token_explicit, "explicit"});
    _token_id.insert({token_builtintype, "builtintype"});
    _token_id.insert({token_taggedmode, "taggedmode"});
    _token_id.insert({token_char, "char"});
    _token_id.insert({token_usertype, "usertype"});
#endif
}

parser::~parser() { delete _ac; }

return_t parser::parse(parser::context& context, const char* p, size_t size) { return context.parse(this, p, size); }

return_t parser::parse(parser::context& context, const char* p) {
    return_t ret = errorcode_t::success;
    if (p) {
        ret = context.parse(this, p, strlen(p));
    } else {
        ret = errorcode_t::invalid_parameter;
    }
    return ret;
}

return_t parser::parse(parser::context& context, const std::string& p) { return parse(context, p.c_str(), p.size()); }

return_t parser::parse(parser::context& context, const basic_stream& p) { return parse(context, p.c_str(), p.size()); }

parser::search_result parser::csearch(const parser::context& context, const char* pattern, size_t size_pattern, unsigned int pos) {
    return context.csearch(this, pattern, size_pattern, pos);  // handle by characters
}

parser::search_result parser::csearch(const parser::context& context, const std::string& pattern, unsigned int pos) {
    return context.csearch(this, pattern, pos);  // handle by characters
}

parser::search_result parser::csearch(const parser::context& context, const basic_stream& pattern, unsigned int pos) {
    return context.csearch(this, pattern, pos);  // handle by characters
}

parser::search_result parser::wsearch(const parser::context& context, const char* pattern, size_t size_pattern, unsigned int pos) {
    return context.wsearch(this, pattern, size_pattern, pos);
}

parser::search_result parser::wsearch(const parser::context& context, const std::string& pattern, unsigned int pos) {
    return context.wsearch(this, pattern, pos);
}

parser::search_result parser::wsearch(const parser::context& context, const basic_stream& pattern, unsigned int pos) {
    return context.wsearch(this, pattern, pos);
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

parser& parser::add_pattern(const char* p, size_t size) {
    if (p) {
        parser::context context;
        parse(context, p, size);
        context.add_pattern(this);
    }
    return *this;
}

parser& parser::add_pattern(const std::string& pattern) { return add_pattern(pattern.c_str(), pattern.size()); }

std::multimap<range_t, unsigned> parser::psearch(const parser::context& context) { return context.psearch(this); }

std::multimap<range_t, unsigned> parser::psearchex(const parser::context& context) { return context.psearchex(this); }

parser& parser::add_token(const std::string& token_name, uint32 attr, uint32 tag) {
    if (false == token_name.empty()) {
        _tokens.add(token_name.c_str(), token_name.size(), new token_attr_tag(attr, tag));
    }
    return *this;
}

parser& parser::add_tokenn(const char* token, size_t size, uint32 attr, uint32 tag) {
    if (token && size) {
        _tokens.add(token, size, new token_attr_tag(attr, tag));
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

bool parser::lookup(const std::string& word, int& index, uint32 flags) {
    bool ret = true;
    int idx = -1;
    if (parse_lookup_readonly & flags) {
        idx = _dictionary.find(word.c_str(), word.size());
        if (-1 == idx) {
            ret = false;
        } else {
            index = idx;
        }
    } else {
        auto node = _dictionary.insert(word.c_str(), word.size());
        index = node->index;
    }
    return ret;
}

bool parser::rlookup(int index, std::string& word) {
    bool ret = true;
    std::vector<char> arr;
    ret = _dictionary.lookup(index, arr);
    if (ret) {
        word.assign(&arr[0], arr.size());
    }
    return ret;
}

bool parser::lookup(const char* p, size_t size, std::string& token_name, uint32& token_type, uint32& token_tag) {
    bool ret = false;
    __try2 {
        if (nullptr == p) {
            __leave2;
        }

        token_type = 0;
        token_tag = 0;
        token_attr_tag* tag = nullptr;
        size_t len = _tokens.lookup(p, size, &tag);
        if (len) {
            token_name.assign(p, len);
            if (tag) {
                token_type = tag->attr;
                token_tag = tag->tag;
            }
            ret = true;
        }
    }
    __finally2 {}
    return ret;
}

void parser::dump(const parser::context& context, basic_stream& bs) {
    int line = 1;
    std::map<int, std::string> color;
    color.insert({token_lvalue, "1;34"});
    color.insert({token_assign, "1;33"});
    color.insert({token_or, "1;32"});
    color.insert({token_word, "1;37"});
    color.insert({token_comments, "0;37"});
    color.insert({token_emphasis, "1;35"});
    color.insert({token_type, "1;36"});

    auto dump_handler = [&](const token_description* desc) -> void {
        if (line != desc->line) {
            bs.printf("\n");
            line = desc->line;
        }
        std::string code = "0;37";
        auto iter = color.find(desc->type);
        if (color.end() != iter) {
            code = iter->second;
            bs.printf("\e[%sm%.*s\e[0m ", code.c_str(), (unsigned)desc->size, desc->p);
        } else {
            bs.printf("%.*s ", (unsigned)desc->size, desc->p);
        }
    };

    context.for_each(dump_handler);
    bs.printf("\n");
}

}  // namespace io
}  // namespace hotplace
