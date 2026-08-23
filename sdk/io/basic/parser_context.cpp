/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   parser_context.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * comments
 *
 */

#include <hotplace/sdk/base/nostd/exception.hpp>
#include <hotplace/sdk/base/nostd/tagged_range_set.hpp>
#include <hotplace/sdk/base/pattern/kmp.hpp>
#include <hotplace/sdk/io/basic/parser.hpp>

namespace hotplace {
namespace io {

parser_context::parser_context() : _parser(nullptr), _p(nullptr), _size(0) {}

parser_context::~parser_context() { clear(); }

return_t parser_context::init(parser* obj, const char* p, size_t size) {
    return_t ret = errorcode_t::success;
    _parser = obj;
    _p = p;
    _size = size;
    get_token().init();
    clear();
    return ret;
}

return_t parser_context::lexparse(parser* obj, const char* p, size_t size, uint32 flags) {
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
        std::multimap<std::string, parser_token*> index;
        parser_token* lvalue = nullptr;
        bool comments = false;
        bool quot = false;

        auto type_of = [&](char c) -> token_t { return ascii2token((byte_t)c); };
        auto hook = [&](int where, parser_token* t) -> bool {
            bool ret_hook = true;
            if (0 == where) {
                switch (get_token().get_tokenid()) {
                    case token_assign:
                        lvalue = last_token();
                        if (lvalue) {
                            lvalue->set_type(token_lvalue);
                            get_token().set_type(token_assign);
                            if (handle_lvalue_usertype) {
                                lvalues.insert(lvalue->get_index());
                            }
                        }
                        break;
                    case token_word: {
                        std::string ts = t->as_string(p);
                        bool test = std::all_of(ts.begin(), ts.end(), ::isdigit);
                        if (test) t->set_type(token_number);
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
                        ret_hook = obj->lookup(ts, entry_no, flags);
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
            // get_token().set_tag(0);
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

            // parser_token
            if (handle_token) {
                std::string item;
                uint32 token_type = 0;
                // uint32 token_tag = 0;
                bool match = obj->lookup(p + pos, size - pos, item, token_type /*, token_tag*/);
                if (match) {
                    add_context_token(hook);

                    get_token().set_type(token_type) /*.set_tag(token_tag)*/;
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
                        if ((token_dquote == type) && (handle_quoted)) {
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

// search_result parser_context::csearch(parser* obj, const char* pattern, size_t size_pattern, size_t pos) const {
//     search_result result;
//     __try2 {
//         if (nullptr == obj || nullptr == pattern) {
//             __leave2;
//         }
//
//         t_kmp<char> kmp;
//         auto idx = kmp.search(_p, _size, pattern, size_pattern, pos);
//         if (size_t(-1) == idx) {
//             __leave2;
//         }
//
//         result.match = true;
//         result.p = _p + idx;
//         result.size = size_pattern;
//         result.pos = idx;
//     }
//     __finally2 {}
//     return result;
// }
//
// search_result parser_context::csearch(parser* obj, const std::string& pattern, size_t pos) const { return csearch(obj, pattern.c_str(), pattern.size(), pos); }
//
// search_result parser_context::csearch(parser* obj, const basic_stream& pattern, size_t pos) const { return csearch(obj, pattern.c_str(), pattern.size(), pos); }
//
// search_result parser_context::wsearch(parser* obj, const parser_context& pattern, size_t pos) const {
//     search_result result;
//     __try2 {
//         if (nullptr == obj) {
//             __leave2;
//         }
//         if (_parser != pattern._parser) {
//             throw exception(errorcode_t::invalid_context);
//             // __leave2;
//         }
//         if (_tokens.empty() || pattern._tokens.empty()) {
//             __leave2;
//         }
//
//         auto comparator = [](const parser_token* lhs, const parser_token* rhs) -> bool { return (lhs->get_index() == rhs->get_index()); };
//
//         t_kmp<parser_token*, decltype(comparator)> kmp(comparator);
//         auto idx = kmp.search(_tokens, pattern._tokens, pos);
//         if (size_t(-1) == idx) {
//             __leave2;
//         }
//
//         size_t size = pattern._tokens.size();
//         wsearch_result(result, idx, size);
//     }
//     __finally2 {}
//     return result;
// }
//
// search_result parser_context::wsearch(parser* obj, const char* pattern, size_t size_pattern, size_t pos) const {
//     // handle by word
//     return_t ret = errorcode_t::success;
//     parser_context pattern_context;
//     ret = pattern_context.lexparse(obj, pattern, size_pattern, parser_flag_t::flat_lookup_readonly);
//     // if success, all words of pattern in dictionary
//     return (errorcode_t::success == ret) ? wsearch(obj, pattern_context, pos) : search_result();
// }
//
// search_result parser_context::wsearch(parser* obj, const std::string& pattern, size_t pos) const { return wsearch(obj, pattern.c_str(), pattern.size(), pos); }
//
// search_result parser_context::wsearch(parser* obj, const basic_stream& pattern, size_t pos) const { return wsearch(obj, pattern.c_str(), pattern.size(), pos); }
//
// bool parser_context::compare(parser* obj, const parser_context& other) const {
//     bool ret = false;
//     if ((_parser == obj) && (_parser == other._parser)) {
//         size_t size = _tokens.size();
//         if (size == other._tokens.size()) {
//             size_t idx = 0;
//             for (idx = 0; idx != size; idx++) {
//                 parser_token* token_lhs = _tokens[idx];
//                 parser_token* token_rhs = other._tokens[idx];
//                 if (((uint32)-1 == token_lhs->get_index()) || (token_lhs->get_index() != token_rhs->get_index())) {
//                     break;
//                 }
//             }
//             if (idx == size) {
//                 ret = true;
//             }
//         }
//     }
//     return ret;
// }
//
// void parser_context::add_pattern(parser* obj) {
//     if (obj) {
//         auto ac = obj->_ac;
//         ac->insert(_tokens.data(), _tokens.size());
//     }
// }
//
// std::multimap<range_t, size_t> parser_context::psearch(parser* obj) const {
//     std::multimap<range_t, size_t> result;
//     if (obj) {
//         auto ac = obj->_ac;
//         ac->build();
//         result = ac->search(_tokens.data(), _tokens.size());
//     }
//     return result;
// }
//
// std::multimap<range_t, size_t> parser_context::psearchex(parser* obj) const {
//     std::multimap<range_t, size_t> result;
//     if (obj) {
//         auto ac = obj->_ac;
//         ac->build();
//         auto acres = ac->search(_tokens.data(), _tokens.size());
//
//         t_tagged_range_set<size_t, size_t> rs;
//         search_result r;
//
//         for (const auto& pair : acres) {
//             // pair(pos_occurrence, id_pattern)
//             const auto& range = pair.first;
//             const auto& pid = pair.second;
//             psearch_result(r, range);
//             rs.add(r.begidx, r.endidx, pid);
//         }
//         auto moires = rs.merge();
//         for (auto item : moires) {
//             range_t range(item.begin, item.end);
//             result.emplace(range, item.t);
//         }
//     }
//     return result;
// }

return_t parser_context::add_context_token(std::function<bool(int, parser_token*)> hook) {
    return_t ret = errorcode_t::success;
    bool ret_hook = true;
    __try2 {
        if (get_token().size()) {
            parser_token* newone = get_token().clone();
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
    __finally2 {}
    return ret;
}

void parser_context::clear() {
    for (auto item : _tokens) {
        delete item;
    }
    _tokens.clear();
}

// void parser_context::wsearch_result(search_result& result, size_t idx, size_t size) const {
//     parser_token* begin = _tokens[idx];
//     parser_token* end = _tokens[idx + size - 1];
//
//     result.match = true;
//     result.p = _p + begin->get_pos();
//     result.size = end->get_pos() - begin->get_pos() + end->get_size();
//     result.pos = begin->get_pos();
//     result.begidx = idx;
//     result.endidx = idx + size - 1;
// }
//
// void parser_context::psearch_result(search_result& result, range_t range) const {
//     parser_token* begin = _tokens[range.begin];
//     parser_token* end = _tokens[range.end];
//
//     result.match = true;
//     result.p = _p + begin->get_pos();
//     result.size = end->get_pos() - begin->get_pos() + end->get_size();
//     result.pos = begin->get_pos();
//     result.begidx = range.begin;
//     result.endidx = range.end;
// }

return_t parser_context::get(size_t index, token_description* desc) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == desc) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        if (index >= _tokens.size()) {
            ret = errorcode_t::out_of_range;
            __leave2;
        }
        auto t = _tokens[index];
        desc->index = index;
        desc->type = t->get_tokenid();
        // desc->tag = t->get_tag();
        desc->pos = t->get_pos();
        desc->size = t->get_size();
        desc->line = t->get_line();
        desc->p = _p + t->get_pos();
    }
    __finally2 {}
    return ret;
}

parser_token& parser_context::get_token() { return _token; }

parser_token* parser_context::last_token() {
    parser_token* t = nullptr;
    if (_tokens.size()) {
        t = _tokens.back();
    }
    return t;
}

void parser_context::for_each(std::function<void(const token_description* desc)> f) const {
    if (_p && f) {
        auto handler = [&](const parser_token* t) -> void {
            // compact parameter
            token_description desc;
            desc.index = t->get_index();
            desc.type = t->get_tokenid();
            // desc.tag = t->get_tag();
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

void parser_context::for_each(const search_result& res, std::function<void(const token_description* desc)> f) const {
    if (res.match && _p && f) {
        auto handler = [&](const parser_token* t) -> void {
            // compact parameter
            token_description desc;
            desc.index = t->get_index();
            desc.type = t->get_tokenid();
            // desc.tag = t->get_tag();
            desc.pos = t->get_pos();
            desc.size = t->get_size();
            desc.line = t->get_line();
            desc.p = _p + t->get_pos();
            f(&desc);
        };

        for (auto i = res.begidx; i <= res.endidx; ++i) {
            auto token = _tokens[i];
            token->visit(_p, handler);
        }
    }
}

void parser_context::walk(std::function<void(const char* p, const parser_token*)> f) {
    if (_p && f) {
        for (auto item : _tokens) {
            f(_p, item);
        }
    }
}

}  // namespace io
}  // namespace hotplace
