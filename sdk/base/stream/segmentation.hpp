/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 *
 * Revision History
 * Date         Name                Description
 *
 * sketch 1 applied
 *
 * sketch 1 (2 phases)
 *      // calc bumper (the size of the fragment header)
 *      // then fragmentation (both pos and len as in parameter)
 *      return_t consume(uint32 type, size_t bumper, std::function<return_t(const byte_t*, size_t, size_t, size_t)> func);
 *
 * sketch 2 (1 phase)
 *      // calc bumper (the size of the fragment header) while fragmentation
 *      // bumper as out parameter in consume method
 */

#ifndef __HOTPLACE_SDK_BASE_STREAM_SEGMENTATION__
#define __HOTPLACE_SDK_BASE_STREAM_SEGMENTATION__

#include <sdk/base/basic/types.hpp>
#include <sdk/base/system/critical_section.hpp>

namespace hotplace {

enum fragment_context_flag_t {
    fragment_context_stream_alloc = (1 << 0),
    fragment_context_keep_entry = (1 << 1),
};

struct fragment_context {
    uint32 type;     // type
    size_t limit;    // segment size
    byte_t* stream;  // stream
    size_t size;     // stream
    size_t pos;      // fragment
    uint32 flags;    // fragment_context_flag_t

    fragment_context() : type(0), limit(0), stream(nullptr), size(0), pos(0), flags(0) {}
    fragment_context(uint32 t, size_t ss, const byte_t* s, size_t n, uint32 f = 0) : type(t), limit(ss), stream(nullptr), size(n), pos(0), flags(f) {
        if (fragment_context_stream_alloc & f) {
            stream = (byte_t*)malloc(n);
            if (stream) {
                memcpy(stream, s, n);
            }
        } else {
            stream = (byte_t*)s;
        }
    }
    fragment_context(const fragment_context& rhs) : type(rhs.type), limit(rhs.limit), stream(nullptr), size(rhs.size), pos(rhs.pos), flags(rhs.flags) {
        if (fragment_context_stream_alloc & flags) {
            stream = (byte_t*)malloc(size);
            if (stream) {
                memcpy(stream, rhs.stream, size);
            }
        } else {
            stream = rhs.stream;
        }
    }
    fragment_context(fragment_context&& rhs) {
        type = rhs.type;
        limit = rhs.limit;
        stream = rhs.stream;
        size = rhs.size;
        pos = rhs.pos;
        flags = rhs.flags;
        rhs.clear(0);
    }
    ~fragment_context() { clear(fragment_context_stream_alloc); }

    void clear(uint32 checkflag = 0) {
        if (stream) {
            if (flags & checkflag & fragment_context_stream_alloc) {
                free(stream);
            }
        }
        type = 0;
        limit = 0;
        stream = nullptr;
        size = 0;
        pos = 0;
        flags = 0;
    }
};

/**
 * @brief segmentation
 * @comments
 *          segmentation segment(get_payload_size());
 *          // construct crypto_data
 *          segment.attach(quic_frame_type_crypto, crypto_data);
 *
 * @sa  quic_packet_publisher::publish_space
 */
class segmentation {
    friend class fragmentation;

   public:
    segmentation(size_t size);

    size_t get_segment_size();

    return_t assign(uint32 type, const byte_t* stream, size_t size, uint32 flags = 0);
    return_t peek(uint32 type, std::function<return_t(const fragment_context& context)> func);
    return_t isready(uint32 type);
    return_t isready();

   protected:
    return_t consume(uint32 type, size_t avail, size_t bumper, std::function<return_t(const byte_t*, size_t, size_t, size_t)> func);

   private:
    critical_section _lock;
    std::map<uint32, fragment_context> _contexts;
    size_t _segment_size;
};

}  // namespace hotplace

#endif
