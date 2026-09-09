/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   lexical_context.cpp
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
#include <hotplace/sdk/base/pattern/kmp.hpp>
#include <hotplace/sdk/io/parser/lexical_analyzer.hpp>

namespace hotplace {
namespace io {

lexical_context::lexical_context() : _p(nullptr), _size(0) {}

lexical_context::~lexical_context() { clear(); }

return_t lexical_context::init(const char* p, size_t size) {
    return_t ret = errorcode_t::success;
    _p = p;
    _size = size;
    clear();
    return ret;
}

return_t lexical_context::add_context_lextoken(const lexical_token& token, std::function<bool(int, lexical_token*)> hook) {
    return_t ret = errorcode_t::success;
    bool ret_hook = true;
    __try2 {
        if (token.empty()) {
            ret = errorcode_t::empty;
            __leave2;
        }

        lexical_token* newone = token.clone();
        if (hook) {
            ret_hook = hook(0, newone);  // pre-action
            if (false == ret_hook) {
                ret = errorcode_t::not_exist;
                delete newone;
                __leave2;
            }
        }
        _lextoken.push_back(newone);
        if (hook) {
            ret_hook = hook(1, newone);  // post-action
            if (false == ret_hook) {
                ret = errorcode_t::not_exist;
                // newone already pushed into _lextoken
                __leave2;
            }
        }
    }
    __finally2 {}
    return ret;
}

void lexical_context::clear() {
    for (auto& item : _lextoken) {
        delete item;
    }
    _lextoken.clear();
}

return_t lexical_context::get(size_t index, token_description* desc) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == desc) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        if (index >= _lextoken.size()) {
            ret = errorcode_t::out_of_range;
            __leave2;
        }
        auto t = _lextoken[index];
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

lexical_token* lexical_context::last_lextoken() {
    lexical_token* t = nullptr;
    if (_lextoken.size()) {
        t = _lextoken.back();
    }
    return t;
}

void lexical_context::for_each(std::function<bool(const token_description* desc)> f) const {
    if (_p && f) {
        size_t idx = 0;
        auto handler = [this, &f, &idx](const lexical_token* t) -> bool {
            // compact parameter
            token_description desc;
            desc.idx = idx++;
            desc.index = t->get_index();
            desc.type = t->get_tokenid();
            // desc.tag = t->get_tag();
            desc.pos = t->get_pos();
            desc.size = t->get_size();
            desc.line = t->get_line();
            desc.p = _p + t->get_pos();
            return f(&desc);
        };

        bool ret = false;
        for (const auto& item : _lextoken) {
            ret = item->visit(_p, handler);
            if (false == ret) {
                break;
            }
        }
    }
}

void lexical_context::for_each(const search_result& res, std::function<bool(const token_description* desc)> f) const {
    if (res.match && _p && f) {
        auto handler = [&](const lexical_token* t) -> bool {
            // compact parameter
            token_description desc;
            desc.index = t->get_index();
            desc.type = t->get_tokenid();
            // desc.tag = t->get_tag();
            desc.pos = t->get_pos();
            desc.size = t->get_size();
            desc.line = t->get_line();
            desc.p = _p + t->get_pos();
            return f(&desc);
        };

        bool ret = false;
        for (auto i = res.begidx; i <= res.endidx; ++i) {
            auto token = _lextoken[i];
            ret = token->visit(_p, handler);
            if (false == ret) {
                break;
            }
        }
    }
}

void lexical_context::walk(std::function<void(const char* p, const lexical_token*)> f) {
    if (_p && f) {
        for (const auto& item : _lextoken) {
            f(_p, item);
        }
    }
}

}  // namespace io
}  // namespace hotplace
