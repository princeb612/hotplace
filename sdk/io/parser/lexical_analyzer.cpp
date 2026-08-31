/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   lexical_analyzer.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * comments
 *
 */

#include <hotplace/sdk/io/parser/lexical_analyzer.hpp>
#include <hotplace/sdk/io/parser/parser_resource.hpp>

namespace hotplace {
namespace io {

lexical_analyzer::lexical_analyzer() {
    // set handle_quoted to 1
    get_config().set("handle_comments", 1).set("handle_quoted", 1).set("handle_token", 1);
    // nameof_token
    auto resource = parser_resource::get_instance();
    resource->for_each(parser_resource_type_t::token_type_basic, [this](uint32 token, const std::string& name) -> void { _token_dbg.emplace(token, name); });
}

lexical_analyzer::~lexical_analyzer() {}

lexical_analyzer& lexical_analyzer::add_token(const std::string& token_name, uint32 token) {
    if (false == token_name.empty()) {
        _lextoken.add(token_name.c_str(), token_name.size(), new token_attr_tag(token));
        _token_dbg.emplace(token, token_name);  // do not overwrite
    }
    return *this;
}

std::string lexical_analyzer::nameof_token(uint32 token) {
    std::string id;
    auto iter = _token_dbg.find(token);
    if (_token_dbg.end() != iter) {
        id = iter->second;
    }
    return id;
}

static bool is_number(const std::string& s) {
    if (s.empty()) return false;

    size_t i = 0;

    if (s[i] == '+' || s[i] == '-') ++i;

    bool digit = false;
    bool dot = false;
    bool exp = false;

    for (; i < s.size(); ++i) {
        char c = s[i];

        if (std::isdigit(static_cast<unsigned char>(c))) {
            digit = true;
            continue;
        }
        if ((c == '.') && (false == dot) && (false == exp)) {
            dot = true;
            continue;
        }
        if ((c == 'e' || c == 'E') && digit && (false == exp)) {
            exp = true;
            digit = false;
            if (i + 1 < s.size() && (s[i + 1] == '+' || s[i + 1] == '-')) {
                ++i;
            }
            continue;
        }
        return false;
    }
    return digit;
}

return_t lexical_analyzer::parse(lexical_context& context, const char* p, size_t size, uint32 flags) {
    return_t ret = errorcode_t::success;
    unsigned error_lookup = 0;
    __try2 {
        if (nullptr == p) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        lexical_token token;

        uint16 handle_comments = get_config().get("handle_comments");
        uint16 handle_quoted = get_config().get("handle_quoted");
        uint16 handle_token = get_config().get("handle_token");
        uint16 handle_quot_as_unquoted = get_config().get("handle_quot_as_unquoted");
        uint16 handle_lvalue_usertype = get_config().get("handle_lvalue_usertype");
        std::set<uint32> lvalues;
        std::multimap<std::string, lexical_token*> index;
        lexical_token* lvalue = nullptr;
        bool comments = false;
        bool quot = false;

        auto type_of = [&](char c) -> token_t { return ascii2token((byte_t)c); };
        auto hook = [&](int where, lexical_token* t) -> bool {
            bool ret_hook = true;
            if (0 == where) {
                switch (token.get_tokenid()) {
                    case token_assign:
                        lvalue = context.last_lextoken();
                        if (lvalue) {
                            lvalue->set_type(token_lvalue);
                            token.set_type(token_assign);
                            if (handle_lvalue_usertype) {
                                lvalues.insert(lvalue->get_index());
                            }
                        }
                        break;
                    case token_word: {
                        std::string ts = t->as_string(p);
                        // bool test = std::all_of(ts.begin(), ts.end(), ::isdigit);
                        // if (test) t->set_type(token_number);
                        if (is_number(ts)) {
                            if (ts.find('.') != std::string::npos || ts.find('e') != std::string::npos || ts.find('E') != std::string::npos) {
                                t->set_type(token_floatingpoint);
                            } else {
                                t->set_type(token_number);
                            }
                        }
                    } break;
                    default:
                        break;
                }
            } else {
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
            // token.set_tag(0);
            return ret_hook;
        };

        context.init(p, size);

        for (size_t pos = 0; (pos < size) && (0 == error_lookup); pos++) {
            char c = p[pos];
            token_t type = type_of(c);

            // comments
            if (comments && handle_comments) {
                if (token_newline == type) {
                    comments = false;

                    context.add_context_lextoken(token, hook);
                    token.update_pos(pos + 1).update_size(0).newline();
                } else {
                    token.increase();
                }
                continue;
            }

            // lexical_token
            if (handle_token) {
                std::string item;
                uint32 token_type = 0;
                // uint32 token_tag = 0;
                bool match = lookup(p + pos, size - pos, item, token_type /*, token_tag*/);
                if (match) {
                    context.add_context_lextoken(token, hook);

                    token.set_type(token_type) /*.set_tag(token_tag)*/;
                    if ((token_comments == token_type) && handle_comments) {
                        comments = true;
                        token.increase();
                    } else {
                        token.update_pos(pos).update_size(item.size());
                        context.add_context_lextoken(token, hook);
                        pos += (item.size() - 1);
                        token.update_pos(pos + 1).update_size(0);
                    }
                    continue;
                }
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
            }

            if (quot) {
                token.increase();
            } else {
                // tokenize
                switch (type) {
                    case token_alpha:
                    case token_number:
                        token.set_type(token_word).increase();
                        break;
                    case token_space:
                        context.add_context_lextoken(token, hook);

                        token.update_pos(pos + 1).update_size(0);
                        break;
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

        if (handle_lvalue_usertype) {
            for (auto idx : lvalues) {
                std::string ts;
                rlookup(idx, ts);
                // printf("idx %i %s\n", idx, ts.c_str());
                add_token(ts, token_usertype);
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

return_t lexical_analyzer::parse(lexical_context& context, const char* p, uint32 flags) {
    if (nullptr == p) return errorcode_t::invalid_parameter;
    return parse(context, p, strlen(p), flags);
}

return_t lexical_analyzer::parse(lexical_context& context, const std::string& p, uint32 flags) { return parse(context, p.c_str(), p.size(), flags); }

return_t lexical_analyzer::parse(lexical_context& context, const basic_stream& p, uint32 flags) { return parse(context, p.c_str(), p.size(), flags); }

t_key_value<std::string, uint16>& lexical_analyzer::get_config() { return _keyvalue; }

bool lexical_analyzer::lookup(const std::string& word, int& index, uint32 flags) {
    bool ret = true;
    int idx = -1;
    if (flat_lookup_readonly & flags) {
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

bool lexical_analyzer::rlookup(int index, std::string& word) {
    bool ret = true;
    std::vector<char> arr;
    ret = _dictionary.lookup(index, arr);
    if (ret) {
        word.assign(arr.data(), arr.size());
    }
    return ret;
}

bool lexical_analyzer::lookup(const char* p, size_t size, std::string& token_name, uint32& token_type /*, uint32& token_tag*/) {
    bool ret = false;
    __try2 {
        if (nullptr == p) {
            __leave2;
        }

        token_type = 0;
        // token_tag = 0;
        token_attr_tag* tag = nullptr;
        size_t len = _lextoken.lookup(p, size, &tag);
        if (len) {
            token_name.assign(p, len);
            if (tag) {
                token_type = tag->attr;
                // token_tag = tag->tag;
            }
            ret = true;
        }
    }
    __finally2 {}
    return ret;
}

void lexical_analyzer::dump(const lexical_context& context, basic_stream& bs) {
    size_t line = 1;
    std::map<int, std::string> color;
    color.emplace(token_lvalue, "1;34");
    color.emplace(token_assign, "1;33");
    color.emplace(token_or, "1;32");
    color.emplace(token_word, "1;37");
    color.emplace(token_comments, "0;37");
    color.emplace(token_emphasis, "1;35");
    color.emplace(token_type, "1;36");

    auto dump_handler = [&](const token_description* desc) -> bool {
        if (line != desc->line) {
            bs.printf("\n");
            line = desc->line;
        }
        std::string code = "0;37";
        auto iter = color.find(desc->type);
        if (color.end() != iter) {
            code = iter->second;
            bs.printf(ANSI_ESCAPE "%sm%.*s" ANSI_ESCAPE "0m ", code.c_str(), (unsigned)desc->size, desc->p);
        } else {
            bs.printf("%.*s ", (unsigned)desc->size, desc->p);
        }
        return true;
    };

    context.for_each(dump_handler);
    bs.printf("\n");
}

}  // namespace io
}  // namespace hotplace
