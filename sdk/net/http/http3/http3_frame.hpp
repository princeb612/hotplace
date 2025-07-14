/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_NET_HTTP_HTTP3_HTTP3FRAME__
#define __HOTPLACE_SDK_NET_HTTP_HTTP3_HTTP3FRAME__

#include <sdk/base/system/critical_section.hpp>
#include <sdk/base/system/shared_instance.hpp>
#include <sdk/net/http/http3/types.hpp>

namespace hotplace {
namespace net {

/**
 * RFC 9114 7.  HTTP Framing Layer
 * RFC 9114 7.2.  Frame Definitions
 */
class http3_frame {
   public:
    return_t read(const byte_t* stream, size_t size, size_t& pos);
    return_t write(binary_t& bin);

    h3_frame_t get_type();

    void addref();
    void release();

   protected:
    http3_frame(h3_frame_t type);

    return_t do_read_frame(const byte_t* stream, size_t size, size_t& pos);
    virtual return_t do_read_payload(const byte_t* stream, size_t size, size_t& pos);
    virtual return_t do_write(binary_t& bin);

    h3_frame_t _type;
    binary_t _payload;
    critical_section _lock;

   private:
    t_shared_reference<http3_frame> _shared;
};

/**
 * RFC 9114 7.2.1.  DATA
 */
class http3_frame_data : public http3_frame {
   public:
    http3_frame_data();

   protected:
    virtual return_t do_read_payload(const byte_t* stream, size_t size, size_t& pos);
    virtual return_t do_write(binary_t& bin);
};

/**
 * RFC 9114 7.2.2.  HEADERS
 */
class http3_frame_headers : public http3_frame {
   public:
    http3_frame_headers(qpack_dynamic_table* dyntable);

   protected:
    virtual return_t do_read_payload(const byte_t* stream, size_t size, size_t& pos);
    virtual return_t do_write(binary_t& bin);

   private:
    qpack_dynamic_table* _dyntable;
};

/**
 * RFC 9114 7.2.3.  CANCEL_PUSH
 */
class http3_frame_cancel_push : public http3_frame {
   public:
    http3_frame_cancel_push();
};

/**
 * RFC 9114 7.2.4.  SETTINGS
 */
class http3_frame_settings : public http3_frame {
   public:
    http3_frame_settings();

   protected:
    virtual return_t do_read_payload(const byte_t* stream, size_t size, size_t& pos);
    virtual return_t do_write(binary_t& bin);
};

/**
 * RFC 9114 7.2.5.  PUSH_PROMISE
 */
class http3_frame_push_promise : public http3_frame {
   public:
    http3_frame_push_promise();
};

/**
 * RFC 9114 7.2.6.  GOAWAY
 */
class http3_frame_goaway : public http3_frame {
   public:
    http3_frame_goaway();
};

/**
 * RFC 9412 The ORIGIN Extension in HTTP/3
 */
class http3_frame_origin : public http3_frame {
   public:
    http3_frame_origin();
};

/**
 * RFC 9114 7.2.7.  MAX_PUSH_ID
 */
class http3_frame_max_push_id : public http3_frame {
   public:
    http3_frame_max_push_id();
};

/**
 * draft
 */
class http3_frame_metadata : public http3_frame {
   public:
    http3_frame_metadata();
};

/**
 * RFC 9114
 */
class http3_frame_priority_update : public http3_frame {
   public:
    http3_frame_priority_update(h3_frame_t type);
};

class http3_frame_unknown : public http3_frame {
   public:
    http3_frame_unknown(uint64 type);
};

class http3_frames {
   public:
    http3_frames();

    return_t read(qpack_dynamic_table* dyntable, const byte_t* stream, size_t size, size_t& pos);
    return_t write(qpack_dynamic_table* dyntable, const byte_t* stream, size_t size);
};

class http3_frame_builder {
   public:
    http3_frame_builder();

    http3_frame_builder& set(h3_frame_t type);
    http3_frame_builder& set(qpack_dynamic_table* dyntable);
    http3_frame* build();

    h3_frame_t get_type();

   private:
    h3_frame_t _type;
    qpack_dynamic_table* _dyntable;
};

}  // namespace net
}  // namespace hotplace

#endif
