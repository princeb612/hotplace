/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   lexical_analyzer_parse.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 * 2009.11.23   Soo Han, Kim        created (codename.merlin)
 * 2024.06.06   Soo Han, Kim        reboot (codename.hotplace)
 * 2026.09.06   Soo Han, Kim        optimize the tokenization loop step by pre-scanning and batch processing the chunk_size upon entering alpha/number tokens.
 *
 * comments
 *
 */

#include <deque>
#include <hotplace/sdk/base/encoding/base16.hpp>
#include <hotplace/sdk/base/string/string.hpp>
#include <hotplace/sdk/io/parser/lexical_analyzer.hpp>
#include <hotplace/sdk/io/parser/parser_resource.hpp>

namespace hotplace {
namespace io {

// Gemini
static size_t scan_float(const char* p, size_t rem_len) {
    if (nullptr == p || 0 == rem_len) return 0;

    size_t idx = 0;
    bool has_digits = false;
    bool has_dot = false;

    if (idx < rem_len && (p[idx] == '+' || p[idx] == '-')) {
        idx++;
    }

    while (idx < rem_len && ::isdigit((byte_t)p[idx])) {
        idx++;
        has_digits = true;
    }

    if (idx < rem_len && p[idx] == '.') {
        if (idx + 1 < rem_len && p[idx + 1] == '.') {
            return 0;
        }
        has_dot = true;
        idx++;

        while (idx < rem_len && ::isdigit((byte_t)p[idx])) {
            idx++;
            has_digits = true;
        }
    }

    if (false == has_dot || false == has_digits) {
        return 0;
    }

    if (idx < rem_len && (p[idx] == 'e' || p[idx] == 'E')) {
        size_t e_start = idx;
        idx++;
        if (idx < rem_len && (p[idx] == '+' || p[idx] == '-')) {
            idx++;
        }
        size_t e_digits = 0;
        while (idx < rem_len && ::isdigit((byte_t)p[idx])) {
            idx++;
            e_digits++;
        }
        if (0 == e_digits) {
            idx = e_start;
        }
    }

    return idx;
}

static bool is_delimiter(uint32 token) {
    bool ret = false;
    switch (token) {
        case token_lbrace:
        case token_rbrace:
        case token_lbracket:
        case token_rbracket:
        case token_lparen:
        case token_rparen:
        case token_comma:
        case token_space:
        case token_lesser:
        case token_greater:
        case token_squote:
            ret = true;
            break;
        default:
            break;
    }
    return ret;
}

return_t lexical_analyzer::parse(lexical_context& context, const char* p, size_t size, uint32 flags) {
    return_t ret = errorcode_t::success;
    unsigned error_lookup = 0;
    __try2 {
        if (nullptr == p || 0 == size) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        lexical_token token;

        uint16 handle_comments = get_config().get("handle_comments");
        uint16 handle_quoted = get_config().get("handle_quoted");
        uint16 handle_squoted = get_config().get("handle_squoted");
        uint16 handle_token = get_config().get("handle_token");
        uint16 handle_quot_as_unquoted = get_config().get("handle_quot_as_unquoted");
        uint16 handle_lvalue_usertype = get_config().get("handle_lvalue_usertype");
        uint16 handle_hexstring = get_config().get("handle_hexstring");  // context-sensitive lexing '01 02'H
        std::map<size_t, uint32> retypes;                                // idx, natice_token_t
        std::multimap<std::string, lexical_token*> index;
        lexical_token* lvalue = nullptr;
        bool comments = false;
        bool quot = false;
        bool squot = false;

        if (handle_hexstring) handle_squoted = true;

        auto type_of = [&](char c) -> token_t { return ascii2token((byte_t)c); };
        auto hook = [&](int where, lexical_token* t) -> bool {
            bool ret_hook = true;
            // pre-action
            if (0 == where) {
                switch (token.get_tokenid()) {
                    case token_assign:
                        lvalue = context.last_lextoken();
                        if (lvalue) {
                            if (token_identifier == lvalue->get_tokenid() || token_usertype == lvalue->get_tokenid()) {
                                // case token_identifier token_assign
                                lvalue->set_type(token_lvalue);
                                token.set_type(token_assign);
                                if (handle_lvalue_usertype) {
                                    retypes.emplace(lvalue->get_index(), token_usertype);
                                }
                            }
                        }
                        break;
                    default:
                        break;
                }
            }
            // post-action
            else {
                int entry_no = 0;
                switch (t->get_tokenid()) {
                    case token_comments:
                        // do not lookup
                        entry_no = -1;
                        break;
                    case token_quot_string:
                    default: {
                        std::string ts = t->as_string(p);
                        ret_hook = lookup(ts, entry_no, flags);
                        if (true == ret_hook) {
                            if (handle_lvalue_usertype) {
                                index.emplace(ts, t);
                            }
                        } else {
                            ++error_lookup;
                        }
                    } break;
                }
                t->set_index(entry_no);
            }

            return ret_hook;
        };  // enc of hook

        context.init(p, size);

        for (size_t pos = 0; (pos < size) && (0 == error_lookup); ++pos) {
            char c = p[pos];
            token_t type = type_of(c);
            size_t chunk_size = 0;  // lookahead
            token_t chunk_type = type;

            if (false == comments && false == quot) {
                if (token_alpha == type) {
                    // alpha [alpha | number] +
                    // ASN.1 style ... alpha-alpha (but alpha--alpha not allowd)
                    const char* cur = p + pos;
                    const char* end = p + size;
                    const char* dash = nullptr;
                    while (cur < end) {
                        auto t = type_of(*cur);
                        if (token_alpha == t) {
                            ++cur;
                            dash = nullptr;
                        } else if (token_number == t) {
                            ++cur;
                            dash = nullptr;
                            chunk_type = token_word;
                        } else if (token_dash == t) {
                            if (dash) {
                                // second dot not allowed
                                cur = dash;
                                break;
                            }
                            dash = cur;
                            ++cur;
                        } else {
                            break;
                        }
                    }
                    chunk_size = cur - (p + pos);
                } else if (token_number == type) {
                    // number ... stop at the delimiter
                    const char* cur = p + pos;
                    const char* end = p + size;
                    const char* dot = nullptr;
                    while (cur < end) {
                        auto t = type_of(*cur);
                        if (is_delimiter(t)) break;
                        if (token_dot == t) {
                            if (dot) {
                                // second dot not allowed
                                cur = dot;  // rollback
                                break;
                            }
                            dot = cur;
                        } else if (token_number != t) {
                            chunk_type = token_word;
                        }
                        ++cur;
                    }
                    chunk_size = cur - (p + pos);
                }
            }
            // comments
            if (comments && handle_comments) {
                if (token_newline == type) {
                    comments = false;

                    context.add_context_lextoken(token, hook);
                    token.update_pos(pos + 1).update_size(0).newline();
                } else {
                    token.increase();

                    uint32 t = 0;
                    size_t tpos = pos;
                    while (true) {
                        t = type_of(p[++tpos]);
                        if (token_newline == t || 0 == t) break;
                        token.increase();
                    }
                    pos = tpos - 1;
                }
                continue;
            }

            // quoted string
            if (handle_quoted) {
                if (token_dquote == type) {
                    quot = !quot;
                    if (quot) {
                        context.add_context_lextoken(token, hook);

                        if (handle_quot_as_unquoted) {
                            token.set_type(token_emphasis).update_pos(pos + 1).update_size(0);
                        } else {
                            token.set_type(token_quot_string).update_pos(pos).update_size(1);
                        }
                    } else {
                        if (false == handle_quot_as_unquoted) {
                            token.increase();
                        }
                        context.add_context_lextoken(token, hook);
                        token.update_pos(pos + 1).update_size(0);
                    }
                    continue;
                }
                if (handle_squoted) {
                    if (token_squote == type) {
                        squot = !squot;
                        if (squot) {
                            context.add_context_lextoken(token, hook);
                            token.set_type(token_squot_string).update_pos(pos).update_size(1);
                        } else {
                            token.increase();
                            if (handle_hexstring) {
                                if (pos + 1 < size) {
                                    auto la = p[pos + 1];
                                    if (('H' == la) || ('h' == la)) {
                                        auto begin = token.get_pos() + 1;
                                        auto len = token.get_size() - 2;
                                        if (is_base16_rfc_encoded(p + begin, len)) {
                                            token.set_type(token_hexstring);
                                            // H or h
                                            token.increase();
                                            ++pos;
                                        }
                                    }
                                }
                            }
                            context.add_context_lextoken(token, hook);
                            token.update_pos(pos + 1).update_size(0);
                        }
                        continue;
                    }
                }
            }

            if (quot || squot) {
                token.increase();
            } else {
                if (token_space == type) {
                    context.add_context_lextoken(token, hook);
                    token.update_pos(pos + 1).update_size(0);
                    continue;
                }

                // lexical_token
                if ((token.empty() || is_delimiter(type)) && (handle_comments || handle_token)) {
                    std::string item;
                    uint32 lookup_type = 0;
                    bool match = lookup(p + pos, size - pos, item, lookup_type);
                    if (match) {
                        if ((token_comments == lookup_type) && handle_comments) {
                            token.set_type(lookup_type);
                            token.update_pos(pos).update_size(item.size());
                            pos += (item.size() - 1);
                            comments = true;
                            continue;
                        } else if (handle_token && (false == quot) && (false == comments)) {
                            if (is_delimiter(lookup_type)) {
                                context.add_context_lextoken(token, hook);

                                // punctuators
                                token.set_type(lookup_type);
                                token.update_pos(pos).update_size(item.size());
                                context.add_context_lextoken(token, hook);
                                token.update_pos(pos + item.size()).update_size(0);
                                continue;
                            } else if (token_usertype == lookup_type) {
                                if (false == token.empty()) {
                                    if (token_word == token.get_tokenid()) {
                                        token.update_size(item.size());
                                        pos += (item.size() - 1);
                                        continue;
                                    }
                                } else {
                                    // test boundary
                                    if (chunk_size == item.size()) {
                                        token.set_type(lookup_type);
                                        token.update_pos(pos).update_size(item.size());
                                        context.add_context_lextoken(token, hook);
                                        pos += (item.size() - 1);
                                        token.update_pos(pos + 1).update_size(0);
                                        continue;
                                    }
                                }
                            } else {
                                context.add_context_lextoken(token, hook);

                                token.set_type(lookup_type);
                                token.update_pos(pos).update_size(item.size());
                                context.add_context_lextoken(token, hook);
                                pos += (item.size() - 1);
                                token.update_pos(pos + 1).update_size(0);
                                continue;
                            }
                        }
                    }
                }

                // tokenize
                switch (chunk_type) {
                    case token_word:
                    case token_alpha:
                        token.set_type(token_word).update_size(chunk_size);
                        context.add_context_lextoken(token, hook);
                        pos += (chunk_size - 1);
                        token.update_pos(pos + 1).update_size(0);
                        break;
                    case token_number: {
                        size_t float_len = scan_float(p + pos, size - pos);
                        if (float_len > 0) {
                            context.add_context_lextoken(token, hook);

                            // token_floatingpoint
                            token.set_type(token_floatingpoint).update_pos(pos).update_size(float_len);
                            context.add_context_lextoken(token, hook);

                            pos += (float_len - 1);
                            token.update_pos(pos + 1).update_size(0);
                            break;
                        }

                        if (token_number == type) {
                            // token_number
                            token.set_type(token_number);
                        } else {
                            context.add_context_lextoken(token, hook);

                            token.set_type(type);
                        }
                        token.update_pos(pos).update_size(chunk_size);
                        context.add_context_lextoken(token, hook);
                        pos += (chunk_size - 1);
                        token.update_pos(pos + 1).update_size(0);
                    } break;
                    case token_newline:
                        context.add_context_lextoken(token, hook);

                        token.update_pos(pos + 1).update_size(0).newline();
                        break;
                    case token_dquote:
                    default:
                        if ((token_dquote == type) && (handle_quoted)) {
                            break;
                        }

                        context.add_context_lextoken(token, hook);

                        token.set_type(type).update_pos(pos).update_size(1);
                        context.add_context_lextoken(token, hook);
                        token.update_pos(pos + 1).update_size(0);
                        break;
                }
            }
        }
        context.add_context_lextoken(token, hook);

        /**
         * a preprocessing step that reclassifies identifier tokens of the same spelling using the set of l-value identifiers found in the lexical pass
         *
         *                 source
         *                   │
         *                   ▼
         *              lexical pass
         *                   │
         *           ┌───────┴───────┐
         *           │               │
         *        tokens           retypes
         *                           │
         *                           ▼
         *                     rlookup names
         *                           │
         *                           ▼
         *                   token_usertype
         *                           │
         *                           ▼
         *                 token reclassification
         *                           │
         *                           ▼
         *                         LALR
         */
        if (false == retypes.empty()) {
            for (const auto& pair : retypes) {
                auto idx = pair.first;
                auto type = pair.second;
                std::string ts;
                if (rlookup(idx, ts)) {
                    add_token(ts, type);
                    auto range = index.equal_range(ts);
                    for (auto iter = range.first; iter != range.second; ++iter) {
                        iter->second->set_type(type);
                    }
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

return_t lexical_analyzer::parse(lexical_context& context, const char* p, uint32 flags) {
    if (nullptr == p) return errorcode_t::invalid_parameter;
    return parse(context, p, strlen(p), flags);
}

return_t lexical_analyzer::parse(lexical_context& context, const std::string& p, uint32 flags) { return parse(context, p.c_str(), p.size(), flags); }

return_t lexical_analyzer::parse(lexical_context& context, const basic_stream& p, uint32 flags) { return parse(context, p.c_str(), p.size(), flags); }

}  // namespace io
}  // namespace hotplace
