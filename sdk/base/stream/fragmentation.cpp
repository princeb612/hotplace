/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/base/stream/fragmentation.hpp>
#include <sdk/base/stream/segmentation.hpp>

namespace hotplace {

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
