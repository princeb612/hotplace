/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/base/stream/segmentation.hpp>

namespace hotplace {

segmentation::segmentation(size_t size) : _segment_size(size) {}

size_t segmentation::get_segment_size() { return _segment_size; }

return_t segmentation::assign(uint32 type, const byte_t* stream, size_t size, uint32 flags) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (0 == (fragment_context_forced & flags)) {
            if (nullptr == stream || 0 == size) {
                ret = do_nothing;
                __leave2;
            }
        }

        critical_section_guard guard(_lock);
        auto iter = _contexts.find(type);
        if (_contexts.end() == iter) {
            _contexts.insert({type, std::move(fragment_context(type, get_segment_size(), stream, size, flags))});
        } else {
            ret = errorcode_t::already_exist;
        }
    }
    __finally2 {}
    return ret;
}

return_t segmentation::peek(uint32 type, std::function<return_t(const fragment_context& context)> func) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == func) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        critical_section_guard guard(_lock);
        auto iter = _contexts.find(type);
        if (_contexts.end() == iter) {
            ret = errorcode_t::not_ready;
            __leave2;
        } else {
            const auto& context = iter->second;
            ret = func(context);
        }
    }
    __finally2 {}
    return ret;
}

return_t segmentation::consume(uint32 type, size_t avail, size_t bumper, std::function<return_t(const byte_t*, size_t, size_t, size_t)> func) {
    return_t ret = errorcode_t::success;
    __try2 {
        if ((nullptr == func) || (avail < bumper)) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        critical_section_guard guard(_lock);
        auto iter = _contexts.find(type);
        if (_contexts.end() == iter) {
            ret = errorcode_t::not_ready;
            __leave2;
        } else {
            auto& context = iter->second;

            size_t payloadlen = avail - bumper;
            size_t space = context.size - context.pos;
            size_t len = (space > payloadlen) ? payloadlen : space;

            ret = func(context.stream, context.size, context.pos, len);

            context.pos += len;

            if (context.size == context.pos) {
                if (fragment_context_forced & context.flags) {
                    context.clear();
                    context.flags = fragment_context_forced;
                } else {
                    _contexts.erase(iter);
                }
            }
        }
    }
    __finally2 {}
    return ret;
}

return_t segmentation::isready(uint32 type) {
    return_t ret = errorcode_t::success;
    __try2 {
        critical_section_guard guard(_lock);
        auto iter = _contexts.find(type);
        if (_contexts.end() == iter) {
            ret = errorcode_t::not_ready;
            __leave2;
        } else {
            auto& context = iter->second;
            if (context.pos >= context.size) {
                ret = errorcode_t::no_more;
            }
        }
    }
    __finally2 {}
    return ret;
}

return_t segmentation::isready() {
    return_t ret = errorcode_t::success;
    __try2 {
        critical_section_guard guard(_lock);
        if (_contexts.empty()) {
            ret = errorcode_t::not_ready;
            __leave2;
        } else {
            for (auto& item : _contexts) {
                auto& context = item.second;
                if (context.pos >= context.size) {
                    ret = errorcode_t::no_more;
                    break;
                }
            }
        }
    }
    __finally2 {}
    return ret;
}

}  // namespace hotplace
