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

#include <sdk/base/nostd/exception.hpp>
#include <sdk/base/nostd/ovl.hpp>
#include <sdk/base/pattern/kmp.hpp>
#include <sdk/io/basic/parser.hpp>

namespace hotplace {
namespace io {

struct ascii_token_table {
    uint8 code;
    const char* symbol;
    token_t type;
} _ascii_token_table[256]{
    {0x00, "NUL", token_unknown},  {0x01, "SOH", token_unknown}, {0x02, "STX", token_unknown}, {0x03, "ETX", token_unknown},  {0x04, "EOT", token_unknown},
    {0x05, "ENQ", token_unknown},  {0x06, "ACK", token_unknown}, {0x07, "BEL", token_unknown}, {0x08, "BS", token_unknown},   {0x09, "HT", token_unknown},
    {0x0A, "LF", token_newline},   {0x0B, "VT", token_unknown},  {0x0C, "FF", token_unknown},  {0x0D, "CR", token_unknown},   {0x0E, "SO", token_unknown},
    {0x0F, "SI", token_unknown},   {0x10, "DLE", token_unknown}, {0x11, "DC1", token_unknown}, {0x12, "DC2", token_unknown},  {0x13, "DC3", token_unknown},
    {0x14, "DC4", token_unknown},  {0x15, "NAK", token_unknown}, {0x16, "SYN", token_unknown}, {0x17, "ETB", token_unknown},  {0x18, "CAN", token_unknown},
    {0x19, "EM", token_unknown},   {0x1A, "SUB", token_unknown}, {0x1B, "ESC", token_unknown}, {0x1C, "FS", token_unknown},   {0x1D, "GS", token_unknown},
    {0x1E, "RS", token_unknown},   {0x1F, "US", token_unknown},  {0x20, "SP", token_space},    {0x21, "!", token_unknown},    {0x22, "\"", token_dquote},
    {0x23, "#", token_unknown},    {0x24, "$", token_unknown},   {0x25, "%", token_unknown},   {0x26, "&", token_and},        {0x27, "'", token_squote},
    {0x28, "(", token_lparen},     {0x29, ")", token_rparen},    {0x2A, "*", token_multi},     {0x2B, "+", token_plus},       {0x2C, ",", token_comma},
    {0x2D, "-", token_minus},      {0x2E, ".", token_dot},       {0x2F, "/", token_divide},    {0x30, "0", token_number},     {0x31, "1", token_number},
    {0x32, "2", token_number},     {0x33, "3", token_number},    {0x34, "4", token_number},    {0x35, "5", token_number},     {0x36, "6", token_number},
    {0x37, "7", token_number},     {0x38, "8", token_number},    {0x39, "9", token_number},    {0x3A, ":", token_colon},      {0x3B, ";", token_semicolon},
    {0x3C, "<", token_lesser},     {0x3D, "=", token_equal},     {0x3E, ">", token_greater},   {0x3F, "?", token_unknown},    {0x40, "@", token_unknown},
    {0x41, "A", token_alpha},      {0x42, "B", token_alpha},     {0x43, "C", token_alpha},     {0x44, "D", token_alpha},      {0x45, "E", token_alpha},
    {0x46, "F", token_alpha},      {0x47, "G", token_alpha},     {0x48, "H", token_alpha},     {0x49, "I", token_alpha},      {0x4A, "J", token_alpha},
    {0x4B, "K", token_alpha},      {0x4C, "L", token_alpha},     {0x4D, "M", token_alpha},     {0x4E, "N", token_alpha},      {0x4F, "O", token_alpha},
    {0x50, "P", token_alpha},      {0x51, "Q", token_alpha},     {0x52, "R", token_alpha},     {0x53, "S", token_alpha},      {0x54, "T", token_alpha},
    {0x55, "U", token_alpha},      {0x56, "V", token_alpha},     {0x57, "W", token_alpha},     {0x58, "X", token_alpha},      {0x59, "Y", token_alpha},
    {0x5A, "Z", token_alpha},      {0x5B, "[", token_lbracket},  {0x5C, "\\", token_unknown},  {0x5D, "]", token_rbracket},   {0x5E, "^", token_unknown},
    {0x5F, "_", token_unknown},    {0x60, "`", token_unknown},   {0x61, "a", token_alpha},     {0x62, "b", token_alpha},      {0x63, "c", token_alpha},
    {0x64, "d", token_alpha},      {0x65, "e", token_alpha},     {0x66, "f", token_alpha},     {0x67, "g", token_alpha},      {0x68, "h", token_alpha},
    {0x69, "i", token_alpha},      {0x6A, "j", token_alpha},     {0x6B, "k", token_alpha},     {0x6C, "l", token_alpha},      {0x6D, "m", token_alpha},
    {0x6E, "n", token_alpha},      {0x6F, "o", token_alpha},     {0x70, "p", token_alpha},     {0x71, "q", token_alpha},      {0x72, "r", token_alpha},
    {0x73, "s", token_alpha},      {0x74, "t", token_alpha},     {0x75, "u", token_alpha},     {0x76, "v", token_alpha},      {0x77, "w", token_alpha},
    {0x78, "x", token_alpha},      {0x79, "y", token_alpha},     {0x7A, "z", token_alpha},     {0x7B, "{", token_lbrace},     {0x7C, "|", token_or},
    {0x7D, "}", token_rbrace},     {0x7E, "~", token_unknown},   {0x7F, "DEL", token_unknown}, {0x80, "€", token_unknown},    {0x81, "", token_unknown},
    {0x82, "‚", token_unknown},    {0x83, "ƒ", token_unknown},   {0x84, "„", token_unknown},   {0x85, "…", token_unknown},    {0x86, "†", token_unknown},
    {0x87, "‡", token_unknown},    {0x88, "ˆ", token_unknown},   {0x89, "‰", token_unknown},   {0x8A, "Š", token_unknown},    {0x8B, "‹", token_unknown},
    {0x8C, "Œ", token_unknown},    {0x8D, "", token_unknown},    {0x8E, "Ž", token_unknown},   {0x8F, "", token_unknown},     {0x90, "", token_unknown},
    {0x91, "‘", token_unknown},    {0x92, "’", token_unknown},   {0x93, "“", token_unknown},   {0x94, "”", token_unknown},    {0x95, "•", token_unknown},
    {0x96, "–", token_unknown},    {0x97, "—", token_unknown},   {0x98, "˜", token_unknown},   {0x99, "™", token_unknown},    {0x9A, "š", token_unknown},
    {0x9B, "›", token_unknown},    {0x9C, "œ", token_unknown},   {0x9D, "", token_unknown},    {0x9E, "ž", token_unknown},    {0x9F, "Ÿ", token_unknown},
    {0xA0, "NBSP", token_unknown}, {0xA1, "¡", token_unknown},   {0xA2, "¢", token_unknown},   {0xA3, "£", token_unknown},    {0xA4, "¤", token_unknown},
    {0xA5, "¥", token_unknown},    {0xA6, "¦", token_unknown},   {0xA7, "§", token_unknown},   {0xA8, "¨", token_unknown},    {0xA9, "©", token_unknown},
    {0xAA, "ª", token_unknown},    {0xAB, "«", token_unknown},   {0xAC, "¬", token_unknown},   {0xAD, "­SHY", token_unknown}, {0xAE, "®", token_unknown},
    {0xAF, "¯", token_unknown},    {0xB0, "°", token_unknown},   {0xB1, "±", token_unknown},   {0xB2, "²", token_unknown},    {0xB3, "³", token_unknown},
    {0xB4, "´", token_unknown},    {0xB5, "µ", token_unknown},   {0xB6, "¶", token_unknown},   {0xB7, "·", token_unknown},    {0xB8, "¸", token_unknown},
    {0xB9, "¹", token_unknown},    {0xBA, "º", token_unknown},   {0xBB, "»", token_unknown},   {0xBC, "¼", token_unknown},    {0xBD, "½", token_unknown},
    {0xBE, "¾", token_unknown},    {0xBF, "¿", token_unknown},   {0xC0, "À", token_unknown},   {0xC1, "Á", token_unknown},    {0xC2, "Â", token_unknown},
    {0xC3, "Ã", token_unknown},    {0xC4, "Ä", token_unknown},   {0xC5, "Å", token_unknown},   {0xC6, "Æ", token_unknown},    {0xC7, "Ç", token_unknown},
    {0xC8, "È", token_unknown},    {0xC9, "É", token_unknown},   {0xCA, "Ê", token_unknown},   {0xCB, "Ë", token_unknown},    {0xCC, "Ì", token_unknown},
    {0xCD, "Í", token_unknown},    {0xCE, "Î", token_unknown},   {0xCF, "Ï", token_unknown},   {0xD0, "Ð", token_unknown},    {0xD1, "Ñ", token_unknown},
    {0xD2, "Ò", token_unknown},    {0xD3, "Ó", token_unknown},   {0xD4, "Ô", token_unknown},   {0xD5, "Õ", token_unknown},    {0xD6, "Ö", token_unknown},
    {0xD7, "×", token_unknown},    {0xD8, "Ø", token_unknown},   {0xD9, "Ù", token_unknown},   {0xDA, "Ú", token_unknown},    {0xDB, "Û", token_unknown},
    {0xDC, "Ü", token_unknown},    {0xDD, "Ý", token_unknown},   {0xDE, "Þ", token_unknown},   {0xDF, "ß", token_unknown},    {0xE0, "à", token_unknown},
    {0xE1, "á", token_unknown},    {0xE2, "â", token_unknown},   {0xE3, "ã", token_unknown},   {0xE4, "ä", token_unknown},    {0xE5, "å", token_unknown},
    {0xE6, "æ", token_unknown},    {0xE7, "ç", token_unknown},   {0xE8, "è", token_unknown},   {0xE9, "é", token_unknown},    {0xEA, "ê", token_unknown},
    {0xEB, "ë", token_unknown},    {0xEC, "ì", token_unknown},   {0xED, "í", token_unknown},   {0xEE, "î", token_unknown},    {0xEF, "ï", token_unknown},
    {0xF0, "ð", token_unknown},    {0xF1, "ñ", token_unknown},   {0xF2, "ò", token_unknown},   {0xF3, "ó", token_unknown},    {0xF4, "ô", token_unknown},
    {0xF5, "õ", token_unknown},    {0xF6, "ö", token_unknown},   {0xF7, "÷", token_unknown},   {0xF8, "ø", token_unknown},    {0xF9, "ù", token_unknown},
    {0xFA, "ú", token_unknown},    {0xFB, "û", token_unknown},   {0xFC, "ü", token_unknown},   {0xFD, "ý", token_unknown},    {0xFE, "þ", token_unknown},
    {0xFF, "ÿ", token_unknown},
};

parser::context::context() : _parser(nullptr), _p(nullptr), _size(0) {}

parser::context::~context() { clear(); }

return_t parser::context::init(parser* obj, const char* p, size_t size) {
    return_t ret = errorcode_t::success;
    _parser = obj;
    _p = p;
    _size = size;
    get_token().init();
    clear();
    return ret;
}

return_t parser::context::parse(parser* obj, const char* p, size_t size, uint32 flags) {
    return_t ret = errorcode_t::success;
    unsigned error_lookup = 0;
    __try2 {
        if (nullptr == obj || nullptr == p) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        uint16 handle_comments = obj->get_config().get("handle_comments");
        uint16 handle_quoted = obj->get_config().get("handle_quoted");
        uint16 handle_token = obj->get_config().get("handle_token");
        uint16 handle_quot_as_unquoted = obj->get_config().get("handle_quot_as_unquoted");
        uint16 handle_lvalue_usertype = obj->get_config().get("handle_lvalue_usertype");
        std::set<uint32> lvalues;
        std::multimap<std::string, parser::token*> index;
        parser::token* lvalue = nullptr;
        bool comments = false;
        bool quot = false;

        auto type_of = [&](char c) -> token_t { return _ascii_token_table[c].type; };
        auto hook = [&](int where, parser::token* t) -> bool {
            bool ret_hook = true;
            if (0 == where) {
                parser::token* prev = nullptr;
                switch (get_token().get_type()) {
                    case token_assign:
                        lvalue = last_token();
                        if (lvalue) {
                            lvalue->set_type(token_lvalue);
                            get_token().set_type(token_assign);
                            if (handle_lvalue_usertype) {
                                lvalues.insert(lvalue->get_index());
                                // printf("add lvalue idx %i\n", lvalue->get_index());
                            }
                        }
                        break;
                    default:
                        break;
                }
            } else {
                int entry_no = 0;
                switch (t->get_type()) {
                    case token_comments:
                        // do not lookup
                        entry_no = -1;
                        break;
                    case token_quot_string:
                    default: {
                        std::string ts = t->as_string(p);
                        ret_hook = obj->lookup(ts, entry_no, flags);
                        if (true == ret_hook) {
                            if (handle_lvalue_usertype) {
                                index.insert({ts, t});
                            }
                        } else {
                            ++error_lookup;
                        }
                    } break;
                }
                t->set_index(entry_no);
            }
            get_token().set_tag(0);
            return ret_hook;
        };

        init(obj, p, size);

        for (size_t pos = 0; (pos < size) && (0 == error_lookup); pos++) {
            char c = p[pos];
            token_t type = type_of(c);

            // comments
            if (comments && handle_comments) {
                if (token_newline == type) {
                    comments = false;

                    add_context_token(hook);
                    get_token().update_pos(pos + 1).update_size(0).newline();
                } else {
                    get_token().increase();
                }
                continue;
            }

            // parser::token
            if (handle_token) {
                std::string item;
                uint32 token_type = 0;
                uint32 token_tag = 0;
                bool match = obj->lookup(p + pos, size - pos, item, token_type, token_tag);
                if (match) {
                    add_context_token(hook);

                    get_token().set_type(token_type).set_tag(token_tag);
                    if ((token_comments == token_type) && handle_comments) {
                        comments = true;
                        get_token().increase();
                    } else {
                        get_token().update_pos(pos).update_size(item.size());
                        add_context_token(hook);
                        pos += (item.size() - 1);
                        get_token().update_pos(pos + 1).update_size(0);
                    }
                    continue;
                }
            }

            // quoted string
            if (handle_quoted) {
                if (token_dquote == type) {
                    quot = !quot;
                    if (quot) {
                        add_context_token(hook);

                        if (handle_quot_as_unquoted) {
                            get_token().set_type(token_emphasis).update_pos(pos + 1).update_size(0);
                        } else {
                            get_token().set_type(token_quot_string).update_pos(pos).update_size(1);
                        }
                    } else {
                        if (false == handle_quot_as_unquoted) {
                            get_token().increase();
                        }
                        add_context_token(hook);
                        get_token().update_pos(pos + 1).update_size(0);
                    }
                    continue;
                }
            }

            if (quot) {
                get_token().increase();
            } else {
                // tokenize
                switch (type) {
                    case token_alpha:
                    case token_number:
                        get_token().set_type(token_word).increase();
                        break;
                    case token_space:
                        add_context_token(hook);

                        get_token().update_pos(pos + 1).update_size(0);
                        break;
                    case token_newline:
                        add_context_token(hook);

                        get_token().update_pos(pos + 1).update_size(0).newline();
                        break;
                    case token_dquote:
                    default:
                        if ((token_dquote == type) && (true == handle_quoted)) {
                            break;
                        }

                        add_context_token(hook);

                        get_token().set_type(type).update_pos(pos).update_size(1);
                        add_context_token(hook);
                        get_token().update_pos(pos + 1).update_size(0);
                        break;
                }
            }
        }
        add_context_token(hook);

        if (handle_lvalue_usertype) {
            for (auto idx : lvalues) {
                std::string ts;
                obj->rlookup(idx, ts);
                // printf("idx %i %s\n", idx, ts.c_str());
                obj->add_token(ts, token_usertype);
                auto liter = index.lower_bound(ts);
                auto uiter = index.upper_bound(ts);
                for (auto iter = liter; iter != uiter; iter++) {
                    iter->second->set_type(token_usertype);
                }
            }
        }
    }
    __finally2 {
        if (error_lookup) {
            ret = errorcode_t::not_exist;
        }
    }
    return ret;
}

parser::search_result parser::context::csearch(parser* obj, const char* pattern, size_t size_pattern, unsigned int pos) const {
    search_result result;
    __try2 {
        if (nullptr == obj || nullptr == pattern) {
            __leave2;
        }

        t_kmp<char> kmp;
        int idx = kmp.search(_p, _size, pattern, size_pattern, pos);
        if (-1 == idx) {
            __leave2;
        }

        result.match = true;
        result.p = _p + idx;
        result.size = size_pattern;
        result.pos = idx;
    }
    __finally2 {
        // do nothing
    }
    return result;
}

parser::search_result parser::context::csearch(parser* obj, const std::string& pattern, unsigned int pos) const {
    return csearch(obj, pattern.c_str(), pattern.size(), pos);
}

parser::search_result parser::context::csearch(parser* obj, const basic_stream& pattern, unsigned int pos) const {
    return csearch(obj, pattern.c_str(), pattern.size(), pos);
}

parser::search_result parser::context::wsearch(parser* obj, const context& pattern, unsigned int pos) const {
    search_result result;
    __try2 {
        if (nullptr == obj) {
            __leave2;
        }
        if (_parser != pattern._parser) {
            throw exception(errorcode_t::invalid_context);
            // __leave2;
        }
        if (_tokens.empty() || pattern._tokens.empty()) {
            __leave2;
        }

        auto comparator = [](const parser::token* lhs, const parser::token* rhs) -> bool { return (lhs->get_index() == rhs->get_index()); };

        t_kmp<parser::token*> kmp;
        int idx = kmp.search(_tokens, pattern._tokens, pos, comparator);
        if (-1 == idx) {
            __leave2;
        }

        size_t size = pattern._tokens.size();
        wsearch_result(result, idx, size);
    }
    __finally2 {
        // do nothing
    }
    return result;
}

parser::search_result parser::context::wsearch(parser* obj, const char* pattern, size_t size_pattern, unsigned int pos) const {
    // handle by word
    return_t ret = errorcode_t::success;
    parser::context pattern_context;
    ret = pattern_context.parse(obj, pattern, size_pattern, parser_flag_t::parse_lookup_readonly);
    // if success, all words of pattern in dictionary
    return (errorcode_t::success == ret) ? wsearch(obj, pattern_context, pos) : search_result();
}

parser::search_result parser::context::wsearch(parser* obj, const std::string& pattern, unsigned int pos) const {
    return wsearch(obj, pattern.c_str(), pattern.size(), pos);
}

parser::search_result parser::context::wsearch(parser* obj, const basic_stream& pattern, unsigned int pos) const {
    return wsearch(obj, pattern.c_str(), pattern.size(), pos);
}

bool parser::context::compare(parser* obj, const parser::context& rhs) const {
    bool ret = false;
    if ((_parser == obj) && (_parser == rhs._parser)) {
        size_t size = _tokens.size();
        if (size == rhs._tokens.size()) {
            size_t idx = 0;
            for (idx = 0; idx != size; idx++) {
                parser::token* token_lhs = _tokens[idx];
                parser::token* token_rhs = rhs._tokens[idx];
                if (token_lhs->get_index() != token_lhs->get_index()) {
                    break;
                }
            }
            if (idx == size) {
                ret = true;
            }
        }
    }
    return ret;
}

void parser::context::add_pattern(parser* obj) {
    if (obj) {
        auto ac = obj->_ac;
        ac->insert(&_tokens[0], _tokens.size());
    }
}

std::multimap<range_t, unsigned> parser::context::psearch(parser* obj) const {
    std::multimap<range_t, unsigned> result;
    if (obj) {
        auto ac = obj->_ac;
        ac->build();
        result = ac->search(&_tokens[0], _tokens.size());
    }
    return result;
}

std::multimap<range_t, unsigned> parser::context::psearchex(parser* obj) const {
    std::multimap<range_t, unsigned> result;
    if (obj) {
        auto ac = obj->_ac;
        ac->build();
        auto acres = ac->search(&_tokens[0], _tokens.size());

        t_merge_ovl_intervals<unsigned int, int> moi;  // unsigned int pos, int patternid
        search_result r;

        for (const auto& pair : acres) {
            // pair(pos_occurrence, id_pattern)
            const auto& range = pair.first;
            const auto& pid = pair.second;
            psearch_result(r, range);
            moi.add(r.begidx, r.endidx, pid);
        }
        auto moires = moi.merge();
        for (auto item : moires) {
            range_t range(item.s, item.e);
            result.insert({range, item.t});
        }
    }
    return result;
}

return_t parser::context::add_context_token(std::function<bool(int, parser::token*)> hook) {
    return_t ret = errorcode_t::success;
    bool ret_hook = true;
    __try2 {
        if (get_token().size()) {
            parser::token* newone = get_token().clone();
            if (hook) {
                ret_hook = hook(0, newone);
                if (false == ret_hook) {
                    ret = errorcode_t::not_exist;
                    __leave2;
                }
            }
            _tokens.push_back(newone);
            if (hook) {
                ret_hook = hook(1, newone);
                if (false == ret_hook) {
                    ret = errorcode_t::not_exist;
                    __leave2;
                }
            }
        } else {
            ret = errorcode_t::empty;
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

void parser::context::clear() {
    for (auto item : _tokens) {
        delete item;
    }
    _tokens.clear();
}

void parser::context::wsearch_result(search_result& result, uint32 idx, size_t size) const {
    token* begin = _tokens[idx];
    token* end = _tokens[idx + size - 1];

    result.match = true;
    result.p = _p + begin->get_pos();
    result.size = end->get_pos() - begin->get_pos() + end->get_size();
    result.pos = begin->get_pos();
    result.begidx = idx;
    result.endidx = idx + size - 1;
}

void parser::context::psearch_result(search_result& result, range_t range) const {
    token* begin = _tokens[range.begin];
    token* end = _tokens[range.end];

    result.match = true;
    result.p = _p + begin->get_pos();
    result.size = end->get_pos() - begin->get_pos() + end->get_size();
    result.pos = begin->get_pos();
    result.begidx = range.begin;
    result.endidx = range.end;
}

return_t parser::context::get(uint32 index, token_description* desc) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == desc) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        if (index > _tokens.size()) {
            ret = errorcode_t::out_of_range;
            __leave2;
        }
        auto t = _tokens[index];
        desc->index = index;
        desc->type = t->get_type();
        desc->tag = t->get_tag();
        desc->pos = t->get_pos();
        desc->size = t->get_size();
        desc->line = t->get_line();
        desc->p = _p + t->get_pos();
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

parser::token& parser::context::get_token() { return _token; }

parser::token* parser::context::last_token() {
    parser::token* t = nullptr;
    if (_tokens.size()) {
        t = _tokens.back();
    }
    return t;
}

void parser::context::for_each(std::function<void(const token_description* desc)> f) const {
    if (_p && f) {
        auto handler = [&](const parser::token* t) -> void {
            // compact parameter
            token_description desc;
            desc.index = t->get_index();
            desc.type = t->get_type();
            desc.tag = t->get_tag();
            desc.pos = t->get_pos();
            desc.size = t->get_size();
            desc.line = t->get_line();
            desc.p = _p + t->get_pos();
            f(&desc);
        };

        for (auto item : _tokens) {
            item->visit(_p, handler);
        }
    }
}

void parser::context::for_each(const parser::search_result& res, std::function<void(const token_description* desc)> f) const {
    if (res.match && _p && f) {
        auto handler = [&](const parser::token* t) -> void {
            // compact parameter
            token_description desc;
            desc.index = t->get_index();
            desc.type = t->get_type();
            desc.tag = t->get_tag();
            desc.pos = t->get_pos();
            desc.size = t->get_size();
            desc.line = t->get_line();
            desc.p = _p + t->get_pos();
            f(&desc);
        };

        for (int i = res.begidx; i <= res.endidx; i++) {
            auto token = _tokens[i];
            token->visit(_p, handler);
        }
    }
}

void parser::context::walk(std::function<void(const char* p, const parser::token*)> f) {
    if (_p && f) {
        for (auto item : _tokens) {
            f(_p, item);
        }
    }
}

}  // namespace io
}  // namespace hotplace
