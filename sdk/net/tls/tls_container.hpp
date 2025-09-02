/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 */

#ifndef __HOTPLACE_SDK_NET_TLS_TLSCONTAINER__
#define __HOTPLACE_SDK_NET_TLS_TLSCONTAINER__

#include <sdk/base/error.hpp>
#include <sdk/base/syntax.hpp>
#include <sdk/base/system/critical_section.hpp>
#include <sdk/base/system/error.hpp>
#include <sdk/base/types.hpp>
#include <sdk/net/tls/types.hpp>

namespace hotplace {
namespace net {
/**
 * generalization
 *   tls_records
 *   tls_handshakes
 *   tls_extensions
 *   quic_packets
 *   quic_frames
 * TYPE_PTR
 *   tls_record*
 *   tls_handshake*
 *   tls_extension*
 *   quic_packet*
 *   quic_frame*
 * public member methods
 *   ENTITY_TYPE get_type()
 *   addref()
 *   release()
 * distinct_type_in_container
 *   tls_records     no
 *   tls_handshakes  yes
 *   tls_extensions  yes
 *   quic_packets    no
 *   quic_frames     yes
 */
enum tls_container_flag_t {
    distinct_type_in_container = (1 << 0),
};
template <typename TYPE_PTR, typename ENTITY_TYPE>
class t_tls_container {
   public:
    t_tls_container(uint32 flags = 0) : _flags(flags) {}
    virtual ~t_tls_container() { clear(); }

    return_t add(TYPE_PTR item, bool upref = false) {
        return_t ret = errorcode_t::success;
        if (item) {
            if (upref) {
                item->addref();
            }

            critical_section_guard guard(_lock);

            if (distinct_type_in_container & get_flags()) {
                // tls_handshake, tls_extension
                auto type = item->get_type();
                auto iter = _dictionary.find(type);
                if (_dictionary.end() != iter) {
                    // keep the older
                    item->release();
                } else {
                    _dictionary.insert({type, item});
                    _members.push_back(item);
                }
            } else {
                // tls_record
                auto type = item->get_type();
                _members.push_back(item);
            }
        }
        return ret;
    }
    return_t operator<<(TYPE_PTR item) { return add(item); }
    /**
     * do { } while (success == returnof_func);
     */
    return_t for_each(std::function<return_t(TYPE_PTR)> func) {
        return_t ret = errorcode_t::success;
        if (func) {
            critical_section_guard guard(_lock);
            for (auto item : _members) {
                ret = func(item);
                if (errorcode_t::success != ret) {
                    break;
                }
            }
        }
        return ret;
    }
    /**
     * tls_handshake, tls_extension
     */
    TYPE_PTR get(uint8 type, bool upref) {
        critical_section_guard guard(_lock);
        TYPE_PTR obj = nullptr;
        auto iter = _dictionary.find(type);
        if (_dictionary.end() != iter) {
            obj = iter->second;
            if (upref) {
                obj->addref();
            }
        }
        return obj;
    }
    TYPE_PTR getat(size_t index, bool upref = false) {
        critical_section_guard guard(_lock);
        TYPE_PTR obj = nullptr;
        if (index < _members.size()) {
            obj = _members[index];
            if (upref) {
                obj->addref();
            }
        }
        return obj;
    }
    bool empty() { return _members.empty(); }
    size_t size() { return _members.size(); }
    void clear() {
        critical_section_guard guard(_lock);
        for (auto item : _members) {
            item->release();
        }
        _members.clear();
        _dictionary.clear();
    }

    uint32 get_flags() { return _flags; }

    /**
     * sketch
     *
     *  // special case - 2 NST in 1 CRYPTO FRAME
     *  // see quic_packet_publisher
     *  quic_packet_publisher publisher;
     *  publisher.get_handshakes().get_container().set_flags(0);  // turn off distinct_type_in_container
     *  publisher.get_handshakes().add(new tls_handshake_new_session_ticket(session));
     *  publisher.get_handshakes().add(new tls_handshake_new_session_ticket(session));
     *  publisher.publish(...);
     *  // published binary layout
     *  //   1-RTT
     *  //     CRYPTO
     *  //       New Session Ticket
     *  //       New Session Ticket
     */
    void set_flags(uint32 flags) { _flags = flags; }

   protected:
   private:
    uint32 _flags;
    critical_section _lock;
    std::map<ENTITY_TYPE, TYPE_PTR> _dictionary;
    std::vector<TYPE_PTR> _members;
};

template <typename TYPE_PTR, typename ENTITY_TYPE>
class t_tls_distinct_container : public t_tls_container<TYPE_PTR, ENTITY_TYPE> {
   public:
    t_tls_distinct_container() : t_tls_container<TYPE_PTR, ENTITY_TYPE>(distinct_type_in_container) {}
    virtual ~t_tls_distinct_container() {}
};

}  // namespace net
}  // namespace hotplace

#endif
