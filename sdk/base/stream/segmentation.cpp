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

return_t segmentation::assign(uint32 type, const byte_t* stream, size_t size, uint32 flag) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == stream || 0 == size) {
            ret = do_nothing;
            __leave2;
        }

        critical_section_guard guard(_lock);
        auto iter = _contexts.find(type);
        if (_contexts.end() == iter) {
            _contexts.insert({type, std::move(fragment_context(type, get_segment_size(), stream, size, flag))});
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
                _contexts.erase(iter);
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
        }
    }
    __finally2 {}
    return ret;
}

fragmentation::fragmentation() : _segment(nullptr), _fragment_size(0), _used(0) {}

return_t fragmentation::set(segmentation* segment, size_t concat) {
    return_t ret = errorcode_t::success;
    if (nullptr == segment) {
        ret = errorcode_t::invalid_parameter;
    } else {
        _segment = segment;
        auto fragsize = segment->get_segment_size();
        if (fragsize > concat) {
            _fragment_size = fragsize - concat;
        } else {
            ret = errorcode_t::exceed;
        }
    }
    return ret;
}

segmentation* fragmentation::get_segment() { return _segment; }

size_t fragmentation::get_fragment_size() { return _fragment_size; }

return_t fragmentation::use(size_t size) {
    return_t ret = errorcode_t::success;
    auto segment = get_segment();
    if (segment) {
        if (size + _used > get_fragment_size()) {
            ret = errorcode_t::exceed;
        } else {
            _used = size;
        }
    }
    return ret;
}

size_t fragmentation::used() { return _used; }

size_t fragmentation::available() {
    size_t ret_value = 0;
    auto segment = get_segment();
    if (segment) {
        auto fragsize = get_fragment_size();
        if (fragsize > _used) {
            ret_value = fragsize - _used;
        }
    }
    return ret_value;
}

return_t fragmentation::consume(uint32 type, size_t bumper, std::function<return_t(const byte_t*, size_t, size_t, size_t)> func) {
    return_t ret = errorcode_t::success;
    __try2 {
        auto segment = get_segment();
        if (segment) {
            ret = segment->consume(type, available(), bumper, func);
        }
    }
    __finally2 {}
    return ret;
}

}  // namespace hotplace
