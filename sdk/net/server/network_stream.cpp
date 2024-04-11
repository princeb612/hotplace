/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/base/system/critical_section.hpp>
#include <sdk/net/server/network_stream.hpp>

namespace hotplace {
namespace net {

network_stream::network_stream() {
    // do nothing
}

network_stream::~network_stream() {
    // do nothing
}

return_t network_stream::produce(void* buf_read, size_t size_buf_read) {
    return_t ret = errorcode_t::success;
    network_stream_data* buffer_object = nullptr;

    __try2 {
        if (size_buf_read > 0) {
            __try_new_catch(buffer_object, new network_stream_data, ret, __leave2);
            buffer_object->assign(buf_read, size_buf_read);

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
        network_stream_data* first = nullptr;
        network_stream_data* prev = nullptr;

        critical_section_guard guard(_lock);

        if (true == _queue.empty()) {
            ret = errorcode_t::empty;
        } else {
            while (false == _queue.empty()) {
                buffer_object = _queue.front();
                buffer_object->_next = nullptr;
                if (nullptr == first) {
                    first = buffer_object;
                }
                if (nullptr != prev) {
                    prev->_next = buffer_object;
                }
                prev = buffer_object;
                _queue.pop_front();
            }
        }

        *ptr_buffer_object = first;
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

return_t network_stream::write_wo_protocol(network_protocol_group* protocol_group, network_stream* target) {
    return_t ret = errorcode_t::success;

    __try2 {
        critical_section_guard guard(_lock);

        network_stream_data* buffer_object = nullptr;
        while (false == _queue.empty()) {
            buffer_object = _queue.front();

            target->produce(buffer_object->content(), buffer_object->size());

            buffer_object->release();
            _queue.pop_front();
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t network_stream::write_with_protocol(network_protocol_group* protocol_group, network_stream* target) {
    return_t ret = errorcode_t::success;
    return_t dwResult = errorcode_t::success;
    network_stream_data* buffer_object = nullptr;
    network_protocol* protocol = nullptr;

    basic_stream bufstream;

    protocol_state_t state = protocol_state_t::protocol_state_invalid;
    size_t content_pos = 0;
    size_t content_size = 0;
    size_t request_size = 0;

    size_t roll_count = 0;

    bool _run = true;

    int priority = 0;

    __try2 {
        critical_section_guard guard(_lock);

        for (network_stream_list_t::iterator it = _queue.begin(); it != _queue.end(); it++) {
            roll_count++;
            buffer_object = *it;

            bufstream.write(buffer_object->content(), buffer_object->size()); /* append */
            dwResult = protocol_group->is_kind_of(bufstream.data(), bufstream.size(), &protocol);
            __try2 {
                if (errorcode_t::more_data == dwResult) {
                    // do nothing
                } else if (errorcode_t::success == dwResult) {
                    protocol->read_stream(&bufstream, &request_size, &state, &priority);
                    if (protocol_state_t::protocol_state_complete == state) {
                        target->produce(bufstream.data(), request_size);

                        network_stream_list_t::iterator iter_netstream;
                        for (iter_netstream = _queue.begin(); iter_netstream != _queue.end();) {
                            buffer_object = *iter_netstream;
                            content_pos = content_size;
                            content_size += buffer_object->size();
                            if (request_size >= content_size) {
                                buffer_object->release();
                                _queue.erase(iter_netstream++);
                            } else if ((content_pos <= request_size) && (request_size < content_size)) {
                                size_t remain = content_size - request_size;
                                void* ptr = bufstream.data() + request_size;
                                buffer_object->assign(ptr, remain);
                                buffer_object->set_priority(priority);  // set stream priority

                                _run = false;
                                break;
                            }
                        }

                        _run = false;
                    }
                    if (protocol_state_t::protocol_state_crash == state) {
                        network_stream_list_t::iterator iter_netstream;
                        for (network_stream_list_t::iterator iter_netstream = _queue.begin(); iter_netstream != _queue.end(); iter_netstream++) {
                            buffer_object = *iter_netstream;
                            buffer_object->release();
                        }
                        _queue.clear();

                        _run = false;
                    }
                } else {
                    // not in (errorcode_t::success, errorcode_t::more_data)
                    while (roll_count--) {
                        buffer_object = _queue.front();
                        buffer_object->release();
                        _queue.pop_front();
                    }

                    _run = false;
                }
            }
            __finally2 {
                if (protocol) {
                    protocol->release();
                }
            }

            if (false == _run) {
                break;
            }
        }  // for-loop
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
                write_wo_protocol(protocol_group, target);
            } else {
                write_with_protocol(protocol_group, target);
            }
        }
    }
    __finally2 {
        // do nothing
    }

    return ret;
}

network_stream_data::network_stream_data() : _ptr(nullptr), _size(0), _next(nullptr), _priority(0) {
    _instance.make_share(this);
}

network_stream_data::~network_stream_data() {
    if (nullptr != _ptr) {
        free(_ptr);
    }
}

return_t network_stream_data::assign(void* ptr, size_t size) {
    return_t ret = errorcode_t::success;

    void* p = malloc(size);

    if (nullptr == p) {
        ret = errorcode_t::out_of_memory;
    } else {
        memcpy(p, ptr, size);

        if (nullptr != _ptr) {
            free(_ptr);
        }
        _ptr = p;
        _size = size;
    }

    return ret;
}

size_t network_stream_data::size() { return _size; }

void* network_stream_data::content() { return _ptr; }

network_stream_data* network_stream_data::next() { return _next; }

int network_stream_data::get_priority() { return _priority; }

void network_stream_data::set_priority(int priority) { _priority = priority; }

int network_stream_data::addref() { return _instance.addref(); }

int network_stream_data::release() { return _instance.delref(); }

}  // namespace net
}  // namespace hotplace
