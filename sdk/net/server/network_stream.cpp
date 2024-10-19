/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/base/nostd/list.hpp>
#include <sdk/net/server/network_protocol.hpp>
#include <sdk/net/server/network_stream.hpp>

namespace hotplace {
namespace net {

network_stream::network_stream() {
    // do nothing
}

network_stream::~network_stream() {
    // do nothing
}

return_t network_stream::produce(byte_t* buf_read, size_t size_buf_read, const sockaddr_storage_t* addr) {
    return_t ret = errorcode_t::success;
    network_stream_data* buffer_object = nullptr;

    __try2 {
        if (size_buf_read > 0) {
            __try_new_catch(buffer_object, new network_stream_data, ret, __leave2);

            buffer_object->assign(buf_read, size_buf_read);
            if (addr) {
                buffer_object->set_sockaddr(addr);
            }

            critical_section_guard guard(_lock);
            _queue.push_back(buffer_object);
        }
    }
    __finally2 {
        // do nothing
    }

    return ret;
}

bool network_stream::ready() {
    size_t count = 0;

    critical_section_guard guard(_lock);
    count = _queue.size();

    return count > 0;
}

return_t network_stream::consume(network_stream_data** ptr_buffer_object) {
    return_t ret = errorcode_t::success;

    if (nullptr == ptr_buffer_object) {
        ret = errorcode_t::invalid_parameter;
    } else {
        *ptr_buffer_object = nullptr;

        network_stream_data* buffer_object = nullptr;

        t_single_linkable<network_stream_data> single_link;

        critical_section_guard guard(_lock);

        if (true == _queue.empty()) {
            ret = errorcode_t::empty;
        } else {
            while (false == _queue.empty()) {
                single_link.add(_queue.front());
                _queue.pop_front();
            }
        }

        *ptr_buffer_object = single_link.get_head();
    }

    return ret;
}

return_t network_stream::read(network_protocol_group* protocol_group, network_stream* from) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == from) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        ret = from->write(protocol_group, this);
    }
    __finally2 {
        // do nothing
    }

    return ret;
}

return_t network_stream::write(network_protocol_group* protocol_group, network_stream* target) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == target || nullptr == protocol_group) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        critical_section_guard guard(_lock);

        if (true == _queue.empty()) {
            ret = errorcode_t::empty;
        } else {
            if (true == protocol_group->empty()) {
                do_write(target);
            } else {
                /*
                 * after processing one request, check remains
                 * before do_write
                 *      request packet 1 || request packet 2 || ...
                 * after do_write
                 *      request packet 1 in target
                 *      request packet 2 || ... remains
                 * to resolve
                 *      check more_data
                 */
                while (errorcode_t::more_data == do_writep(protocol_group, target))
                    ;
            }
        }
    }
    __finally2 {
        // do nothing
    }

    return ret;
}

return_t network_stream::do_write(network_stream* target) {
    return_t ret = errorcode_t::success;

    __try2 {
        critical_section_guard guard(_lock);

        network_stream_data* buffer_object = nullptr;
        while (false == _queue.empty()) {
            buffer_object = _queue.front();

            target->produce(buffer_object->content(), buffer_object->size(), buffer_object->get_sockaddr());

            buffer_object->release();
            _queue.pop_front();
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t network_stream::do_writep(network_protocol_group* protocol_group, network_stream* target) {
    return_t ret = errorcode_t::success;
    return_t test = errorcode_t::success;

    basic_stream bufstream;

    protocol_state_t state = protocol_state_t::protocol_state_invalid;
    size_t message_size = 0;
    size_t roll_count = 0;
    bool _run = true;
    int priority = 0;

    critical_section_guard guard(_lock);

    for (network_stream_data* buffer_object : _queue) {
        roll_count++;

        network_protocol* protocol = nullptr;
        bufstream.write(buffer_object->content(), buffer_object->size()); /* append */

        test = protocol_group->is_kind_of(bufstream.data(), bufstream.size(), &protocol);  // reference counter ++

        auto lambda = [](network_protocol* object) -> void {
            if (object) {
                object->release();  // reference counter --
            }
        };
        t_promise_on_destroy<network_protocol*>(protocol, lambda);

        if (errorcode_t::more_data == test) {
            // do nothing
        } else if (errorcode_t::success == test) {
            protocol->read_stream(&bufstream, &message_size, &state, &priority);
            switch (state) {
                case protocol_state_t::protocol_state_complete:
                    target->produce(bufstream.data(), message_size, buffer_object->get_sockaddr());
                    _run = false;
                    break;
                case protocol_state_t::protocol_state_forged:
                case protocol_state_t::protocol_state_crash:
                case protocol_state_t::protocol_state_large:
                    _run = false;
                    break;
                default:
                    break;
            }

            if (false == _run) {
                break;
            }
        } else {
            // not in (errorcode_t::success, errorcode_t::more_data)
            while (roll_count--) {
                buffer_object = _queue.front();
                buffer_object->release();
                _queue.pop_front();
            }

            break;
        }
    }  // for-loop

    switch (state) {
        case protocol_state_t::protocol_state_complete: {
            size_t content_pos = 0;
            size_t content_size = 0;
            network_stream_list_t::iterator iter;
            for (iter = _queue.begin(); iter != _queue.end();) {
                auto buffer_object = *iter;
                content_pos = content_size;
                content_size += buffer_object->size();
                if (message_size >= content_size) {
                    buffer_object->release();
                    _queue.erase(iter++);
                    if (message_size == content_size) {
                        if (iter != _queue.end()) {
                            ret = errorcode_t::more_data;
                        }
                        break;
                    }
                } else if ((content_pos <= message_size) && (message_size < content_size)) {
                    size_t remain = content_size - message_size;
                    byte_t* ptr = bufstream.data() + message_size;
                    buffer_object->assign(ptr, remain);
                    buffer_object->set_priority(priority);  // set stream priority
                    ret = errorcode_t::more_data;           // while (more_data == do_write(...));
                    break;
                }
            }
        } break;
        case protocol_state_t::protocol_state_forged:
        case protocol_state_t::protocol_state_crash:
        case protocol_state_t::protocol_state_large:
            for (network_stream_data* buffer_object : _queue) {
                buffer_object->release();
            }
            _queue.clear();
            break;
        default:
            break;
    }

    return ret;
}

network_stream_data::network_stream_data() : _ptr(nullptr), _size(0), _next(nullptr), _priority(0), _addr(nullptr) { _instance.make_share(this); }

network_stream_data::~network_stream_data() {
    if (_ptr) {
        free(_ptr);
    }
    if (_addr) {
        free(_addr);
    }
}

return_t network_stream_data::assign(byte_t* ptr, size_t size) {
    return_t ret = errorcode_t::success;

    void* p = malloc(size);

    if (nullptr == p) {
        ret = errorcode_t::out_of_memory;
    } else {
        memcpy(p, ptr, size);

        if (nullptr != _ptr) {
            free(_ptr);
        }
        _ptr = (byte_t*)p;
        _size = size;
    }

    return ret;
}

size_t network_stream_data::size() { return _size; }

byte_t* network_stream_data::content() { return _ptr; }

network_stream_data* network_stream_data::next() { return _next; }

void network_stream_data::set_next(network_stream_data* next) { _next = next; }

int network_stream_data::get_priority() { return _priority; }

void network_stream_data::set_priority(int priority) { _priority = priority; }

int network_stream_data::addref() { return _instance.addref(); }

int network_stream_data::release() { return _instance.delref(); }

void network_stream_data::set_sockaddr(const sockaddr_storage_t* cliaddr) {
    // store recvfrom sockaddr
    if (cliaddr) {
        if (cliaddr->ss_family) {
            if (nullptr == _addr) {
                _addr = (sockaddr_storage_t*)malloc(sizeof(sockaddr_storage_t));
            }
            if (_addr) {
                memcpy(_addr, cliaddr, sizeof(sockaddr_storage_t));
            }
        }
    }
}

void network_stream_data::get_sockaddr(sockaddr_storage_t* cliaddr) {
    if (cliaddr && _addr) {
        // get recvfrom sockaddr
        memcpy(cliaddr, _addr, sizeof(sockaddr_storage_t));
    }
}

const sockaddr_storage_t* network_stream_data::get_sockaddr() { return _addr; }

}  // namespace net
}  // namespace hotplace
