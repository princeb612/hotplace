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
};

struct fragment_context {
    uint32 type;     // type
    size_t ssize;    // segment size
    byte_t* stream;  // stream
    size_t size;     // stream
    size_t pos;      // fragment
    uint32 flag;     // fragment_context_flag_t

    fragment_context() : type(0), ssize(0), stream(nullptr), size(0), pos(0), flag(0) {}
    fragment_context(uint32 t, size_t ss, const byte_t* s, size_t n, uint32 f = 0) : type(t), ssize(ss), stream(nullptr), size(n), pos(0), flag(f) {
        if (fragment_context_stream_alloc & f) {
            stream = (byte_t*)malloc(n);
            if (stream) {
                memcpy(stream, s, n);
            }
        } else {
            stream = (byte_t*)s;
        }
    }
    fragment_context(const fragment_context& rhs) : type(rhs.type), ssize(rhs.ssize), stream(nullptr), size(rhs.size), pos(rhs.pos), flag(rhs.flag) {
        if (fragment_context_stream_alloc & flag) {
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
        ssize = rhs.ssize;
        stream = rhs.stream;
        size = rhs.size;
        pos = rhs.pos;
        flag = rhs.flag;
        rhs.clear(0);
    }
    ~fragment_context() { clear(fragment_context_stream_alloc); }

    void clear(uint32 checkflag = 0) {
        if (stream) {
            if (flag & checkflag & fragment_context_stream_alloc) {
                free(stream);
            }
        }
        type = 0;
        ssize = 0;
        stream = nullptr;
        size = 0;
        pos = 0;
        flag = 0;
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

    return_t assign(uint32 type, const byte_t* stream, size_t size, uint32 flag = 0);
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

/**
 * @brief fragmentation
 */
class fragmentation {
   public:
    fragmentation();

    return_t consume(uint32 type, size_t bumper, std::function<return_t(const byte_t*, size_t, size_t, size_t)> func);

    return_t set(segmentation* segment, size_t concat = 0);
    segmentation* get_segment();
    size_t get_fragment_size();

    return_t use(size_t size);
    size_t used();
    size_t available();

   protected:
   private:
    segmentation* _segment;
    size_t _fragment_size;
    size_t _used;
};

}  // namespace hotplace

#endif
