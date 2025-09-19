/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_BASE_STREAM_SPLIT__
#define __HOTPLACE_SDK_BASE_STREAM_SPLIT__

#include <hotplace/sdk/base/stream/types.hpp>

namespace hotplace {
namespace io {

enum splitter_flag_t : uint32 {
    splitter_noalloc = 1 << 0,      // splitter::add
    splitter_new_segment = 1 << 7,  // splitter::run
    splitter_new_group = 1 << 8,    // splitter::run
};

/**
 * @brief split
 * @param const byte_t* stream [in]
 * @param size_t size [in]
 * @param size_t fragment_size [in]
 * @param std::function<void(const byte_t*, size_t, size_t, size_t)> fn [in]
 *              const byte_t* stream
 *              size_t size
 *              size_t fragment_offset
 *              size_t fragment_size
 */
return_t split(const binary_t& stream, size_t fragment_size, std::function<void(const byte_t*, size_t, size_t, size_t)> fn);
return_t split(const byte_t* stream, size_t size, size_t fragment_size, std::function<void(const byte_t*, size_t, size_t, size_t)> fn);
/**
 * @brief split
 * @param const byte_t* stream [in]
 * @param size_t size [in]
 * @param size_t fragment_size [in]
 * @param size_t pre [in]
 *                          case fragment_size 50
 *                            if size of last block of previous stream 30
 *                            size of first block of current stream 20 (not 50)
 * @param std::function<void(const byte_t*, size_t, size_t, size_t)> fn [in]
 */
return_t split(const binary_t& stream, size_t fragment_size, size_t pre, std::function<void(const byte_t*, size_t, size_t, size_t)> fn);
return_t split(const byte_t* stream, size_t size, size_t fragment_size, size_t pre, std::function<void(const byte_t*, size_t, size_t, size_t)> fn);

/**
 * @brief splitter
 * @example
 *      // input
 *      //   group stream1 size 100
 *      //   group stream2 size 210
 *      //   group stream3 size 30
 *      //   segment size 80
 *      // output
 *      //   segment #0 group #0 "group1" fragment offset   0 fragment size 80
 *      //   segment #1 group #0 "group1" fragment offset  80 fragment size 20
 *      //   segment #1 group #1 "group2" fragment offset   0 fragment size 60
 *      //   segment #2 group #1 "group2" fragment offset  60 fragment size 80
 *      //   segment #3 group #1 "group2" fragment offset 140 fragment size 70
 *      //   segment #3 group #2 "group3" fragment offset   0 fragment size 10
 *      //   segment #4 group #2 "group3" fragment offset  10 fragment size 20
 *      splitter<std::string> spl;
 *      spl.set_segment_size(80);
 *      spl.add(std::move(stream1), std::move(std::string("group1")));
 *      spl.add(std::move(stream2), std::move(std::string("group2")));
 *      spl.add(std::move(stream3), std::move(std::string("group3")));
 *      int segment = -1;
 *      int group = -1;
 *      auto lambda = [&](uint32 flags, const byte_t* stream, size_t size, size_t fragoffset, size_t fragsize, const std::string& desc) -> void {
 *          if (splitter_flag_t::splitter_new_segment & flags) {
 *              ++segment;
 *          }
 *          if (splitter_flag_t::splitter_new_group & flags) {
 *              ++group;
 *          }
 *          _logger->writeln(R"(segment #%i group #%i "%s" fragment offset %3zi fragment size %zi)", segment, group, desc.c_str(), fragoffset, fragsize);
 *      };
 *      spl.run(lambda);
 */
template <typename DESCRIPTOR_T>
class splitter {
   public:
    splitter();

    /**
     * @brief add
     * @param binary_t&& stream [in]
     * @param DESCRIPTOR_T&& desc [in]
     * @param uint32 flags [inopt] see splitter_flag_t
     */
    void add(binary_t&& stream, DESCRIPTOR_T&& desc, uint32 flags = 0);
    /**
     * @brief add
     * @param const byte_t* stream [in]
     * @param size_t size [in]
     * @param DESCRIPTOR_T&& desc [in]
     * @param uint32 flags [inopt] see splitter_flag_t
     */
    void add(const byte_t* stream, size_t size, DESCRIPTOR_T&& desc, uint32 flags = 0);
    /**
     * @brief set size
     */
    void set_segment_size(size_t segmentsize);
    /*
     * @brief get size
     */
    size_t get_segment_size();
    /**
     * @brief split
     * @param std::function<void(uint32, const byte_t*, size_t, size_t, size_t, const DESCRIPTOR_T&)> func [in]
     *              uint32 flags
     *              const byte_t* stream
     *              size_t size
     *              size_t fragment_offset
     *              size_t fragment_size
     *              const DESCRIPTOR_T& desc
     */
    return_t run(std::function<void(uint32, const byte_t*, size_t, size_t, size_t, const DESCRIPTOR_T& desc)> func);

   protected:
    struct item_t {
        binary_t bin;    // allocated
        byte_t* stream;  // see splitter_noalloc
        size_t size;
        DESCRIPTOR_T desc;
        uint32 flags;

        item_t() : stream(nullptr), size(0), flags(0) {}
    };
    critical_section _lock;
    std::list<item_t> _list;
    size_t _segment_size;
};

template <typename DESCRIPTOR_T>
splitter<DESCRIPTOR_T>::splitter() : _segment_size(128) {}

template <typename DESCRIPTOR_T>
void splitter<DESCRIPTOR_T>::add(binary_t&& stream, DESCRIPTOR_T&& desc, uint32 flags) {
    item_t item;
    item.bin = std::move(stream);
    item.desc = std::move(desc);
    item.flags = flags;

    critical_section_guard guard(_lock);
    _list.push_back(std::move(item));
}

template <typename DESCRIPTOR_T>
void splitter<DESCRIPTOR_T>::add(const byte_t* stream, size_t size, DESCRIPTOR_T&& desc, uint32 flags) {
    item_t item;
    if (splitter_noalloc & flags) {
        item.stream = stream;
        item.size = size;
    } else {
        binary_t bin;
        bin.insert(bin.end(), stream, stream + size);
        item.bin = std::move(bin);
    }
    item.desc = std::move(desc);
    item.flags = flags;

    critical_section_guard guard(_lock);
    _list.push_back(std::move(item));
}

template <typename DESCRIPTOR_T>
void splitter<DESCRIPTOR_T>::set_segment_size(size_t splitsize) {
    return_t ret = errorcode_t::success;
    critical_section_guard guard(_lock);
    if (splitsize <= 1) {
        _segment_size = 2;
    } else {
        _segment_size = splitsize;
    }
}

template <typename DESCRIPTOR_T>
size_t splitter<DESCRIPTOR_T>::get_segment_size() {
    return _segment_size;
}

template <typename DESCRIPTOR_T>
return_t splitter<DESCRIPTOR_T>::run(std::function<void(uint32, const byte_t*, size_t, size_t, size_t, const DESCRIPTOR_T& desc)> func) {
    return_t ret = errorcode_t::success;

    critical_section_guard guard(_lock);

    size_t pre = 0;
    size_t group = 0;
    for (auto item : _list) {
        byte_t* blockstream = nullptr;
        size_t blocksize = 0;
        if (splitter_noalloc & item.flags) {
            blockstream = item.stream;
            blocksize = item.size;
        } else {
            blockstream = item.bin.empty() ? nullptr : &item.bin[0];
            blocksize = item.bin.size();
        }
        auto lambda = [&](const byte_t* stream, size_t size, size_t fragoffset, size_t fragsize) -> void {
            uint32 flags = 0;
            if (0 == pre) {
                flags |= splitter_new_segment;
            }
            if (0 == fragoffset) {
                flags |= splitter_new_group;
            }
            func(flags, stream, size, fragoffset, fragsize, item.desc);

            pre += fragsize;
            pre %= get_segment_size();
        };

        split(blockstream, blocksize, get_segment_size(), pre, lambda);
    }
    _list.clear();

    return ret;
}

}  // namespace io
}  // namespace hotplace

#endif
