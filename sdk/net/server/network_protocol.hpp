/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_NET_SERVER_NETWORKPROTOCOL__
#define __HOTPLACE_SDK_NET_SERVER_NETWORKPROTOCOL__

#include <map>
#include <sdk/base/system/shared_instance.hpp>
#include <sdk/net/types.hpp>

namespace hotplace {
class basic_stream;
namespace net {

enum protocol_state_t {
    protocol_state_invalid = 0, /* unknown state */
    protocol_state_ident,       /* iskindof returns IDENT */
    protocol_state_header,      /* header completed */
    protocol_state_data,        /* data complete */
    protocol_state_complete,    /* all data complete */
    protocol_state_forged,      /* forgery */
    protocol_state_crash,       /* reserved */
    protocol_state_large,       /* constraints */
};

enum protocol_constraints_t {
    protocol_packet_size = 0,
    protocol_constraints_the_end,
};

/**
 * @brief   protocol interpreter
 */
class network_protocol {
   public:
    network_protocol() {
        _shared.make_share(this);
        _constraints.resize(protocol_constraints_t::protocol_constraints_the_end);
    }
    virtual ~network_protocol() {}

    /**
     * @brief check protocol
     * @param   void*           stream          [IN]
     * @param   size_t          stream_size     [IN]
     * @return  errorcode_t::success
     *          errorcode_t::not_supported (if error, do not return errorcode_t::success)
     */
    virtual return_t is_kind_of(void* stream, size_t stream_size) { return errorcode_t::success; }
    /**
     * @brief read stream
     * @param   IBufferStream*      stream          [IN]
     * @param   size_t*             request_size    [IN]
     * @param   protocol_state_t*   state           [OUT]
     * @param   int*                priority        [OUTOPT]
     */
    virtual return_t read_stream(basic_stream* stream, size_t* request_size, protocol_state_t* state, int* priority = nullptr) {
        *state = protocol_state_t::protocol_state_complete;
        return errorcode_t::success;
    }
    /**
     * @brief   constraints
     */
    virtual return_t set_constraints(protocol_constraints_t id, size_t value) {
        return_t ret = errorcode_t::success;
        if (id < protocol_constraints_t::protocol_constraints_the_end) {
            _constraints[id] = value;
        } else {
            ret = errorcode_t::invalid_request;
        }
        return ret;
    }
    virtual size_t get_constraints(protocol_constraints_t id) {
        size_t ret_value = 0;
        if (id < protocol_constraints_t::protocol_constraints_the_end) {
            ret_value = _constraints[id];
        }
        return ret_value;
    }

    /**
     * @brief   id
     */
    virtual const char* protocol_id() = 0;
    /**
     *  bool is_h3 = false;
     *  if (protocol->use_alpn()) {
     *      is_h3 = protocol->is_kind_of(stream, size);  // compare [0x2, 'h', '3']
     *  }
     */
    virtual bool use_alpn() { return false; }

    int addref() { return _shared.addref(); }
    int release() { return _shared.delref(); }

   protected:
   private:
    t_shared_reference<network_protocol> _shared;
    std::vector<size_t> _constraints;
};

class network_protocol_group {
   public:
    network_protocol_group();
    virtual ~network_protocol_group();

    /**
     * @brief   add protocol
     * @param   network_protocol*    protocol        [IN] add protocol and increase reference counter
     * @return  error code (see error.hpp)
     */
    virtual return_t add(network_protocol* protocol);
    /**
     * @brief   operator <<
     * @param   network_protocol*    protocol        [IN]
     * @remarks
     *          add method replacement wo checking return code
     */
    virtual network_protocol_group& operator<<(network_protocol* protocol);
    /**
     * @brief   find
     * @param   const std::string&   protocol_id     [IN]
     * @param   network_protocol**   ptr_protocol    [OUT] referenced, call release
     * @return  error code (see error.hpp)
     */
    virtual return_t find(const std::string& protocol_id, network_protocol** ptr_protocol);
    /**
     * @brief   operator[protocol_id]
     * @example
     *          network_protocol* protocol = protocol_group["http"];
     *          if (nullptr != protocol)
     *          {
     *              //...
     *              prtotocol->release (); // decrease reference counter
     *          }
     */
    virtual network_protocol* operator[](const std::string& protocol_id);
    /**
     * @brief   remove protocol
     * @param   network_protocol*   protocol        [IN] remove protocol and decrease reference counter
     * @return  error code (see error.hpp)
     */
    virtual return_t remove(network_protocol* protocol);
    /**
     * @brief   remove all protocols
     * @return  error code (see error.hpp)
     */
    virtual return_t clear();
    /**
     * @brief is protocol absent
     */
    virtual bool empty();

    /**
     * @brief   find appropriate protocol
     * @param   void*               stream          [IN]
     * @param   size_t              stream_size     [IN]
     * @param   network_protocol**  ptr_protocol    [OUT] referenced, use release to free (important)
     * @return  error code (see error.hpp)
     * @remarks
     *          if input stream is too short, return errorcode_t::more_data
     */
    virtual return_t is_kind_of(void* stream, size_t stream_size, network_protocol** ptr_protocol);

    /**
     * @brief   increase reference counter
     */
    int addref();
    /**
     * @brief   decrease reference counter. if reference counter 0, delete object.
     */
    int release();

   protected:
   private:
    t_shared_reference<network_protocol_group> _shared;

    typedef std::map<std::string, network_protocol*> protocol_map_t;
    typedef std::pair<protocol_map_t::iterator, bool> protocol_map_pib_t;

    critical_section _lock;
    protocol_map_t _protocols;
};

}  // namespace net
}  // namespace hotplace

#endif
