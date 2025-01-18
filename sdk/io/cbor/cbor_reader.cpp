/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *  RFC 7049 Concise Binary Object Representation (CBOR)
 *  RFC 8949 Concise Binary Object Representation (CBOR)
 *
 * Revision History
 * Date         Name                Description
 * 2023.09.01   Soo Han, Kim        refactor
 */

#include <sdk/base/basic/base16.hpp>
#include <sdk/io/cbor/cbor_array.hpp>
#include <sdk/io/cbor/cbor_data.hpp>
#include <sdk/io/cbor/cbor_map.hpp>
#include <sdk/io/cbor/cbor_publisher.hpp>
#include <sdk/io/cbor/cbor_reader.hpp>
#include <sdk/io/stream/stream.hpp>
#include <sdk/io/system/types.hpp>

namespace hotplace {
namespace io {

typedef std::deque<cbor_object*> cbor_item_dequeue_t;
typedef std::list<cbor_object*> cbor_root_t;
typedef struct _cbor_reader_context_temp_t {
    int indef;
    cbor_tag_t tag_value;  // temporary
    bool tag_flag;
    cbor_item_dequeue_t parents;
    cbor_item_dequeue_t items;

    _cbor_reader_context_temp_t() : indef(0), tag_value(cbor_tag_t::cbor_tag_unknown), tag_flag(false) {}
} cbor_reader_context_temp_t;

typedef struct _cbor_reader_context_t {
    cbor_root_t roots;
    cbor_reader_context_temp_t temp;
} cbor_reader_context_t;

cbor_reader::cbor_reader() {
    // do nothing
}

return_t cbor_reader::open(cbor_reader_context_t** handle) {
    return_t ret = errorcode_t::success;
    cbor_reader_context_t* context = nullptr;

    __try2 {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        __try_new_catch(context, new cbor_reader_context_t, ret, __leave2);
        *handle = context;
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t cbor_reader::close(cbor_reader_context_t* handle) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        clear(handle);

        delete handle;
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t cbor_reader::clear(cbor_reader_context_t* handle) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        for (cbor_object* object : handle->roots) {
            object->release();
        }
        handle->roots.clear();

        handle->temp.parents.clear();
        handle->temp.items.clear();
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t cbor_reader::parse(cbor_reader_context_t* handle, const char* expr) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == handle || nullptr == expr) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        binary_t bin;

        bin = base16_decode(expr);
        ret = parse(handle, bin);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t cbor_reader::parse(cbor_reader_context_t* handle, const byte_t* data, size_t size) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == handle || nullptr == data) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        clear(handle);

        size_t i = 0;
        uint32 flags = 0;
        byte_t cur = 0;
        uint32 tag = 0;

        for (i < 0; i < size; i++) {
            cur = *(data + i);
            byte_t lead_type = (cur & 0xe0) >> 5;
            byte_t lead_value = (cur & 0x1f);
#if defined __SIZEOF_INT128__
            int128 value = lead_value;
#else
            int64 value = lead_value;
#endif
            flags = 0;

            // cbor_simple_t::cbor_simple_break
            if ((0xff == cur) && handle->temp.indef) {
                handle->temp.indef--;
                handle->temp.parents.pop_back();
                continue;
            }

            // including cbor_major_t::cbor_major_tag
            if (lead_value >= 24) {
                if (24 == lead_value) {
                    value = *(byte_t*)(data + i + 1);
                    i++;
                } else if (25 == lead_value) {
                    value = *(uint16*)(data + i + 1);
                    value = ntoh16(value);
                    i += 2;
                } else if (26 == lead_value) {
                    value = *(uint32*)(data + i + 1);
                    value = ntoh32(value);
                    i += 4;
                } else if (27 == lead_value) {
                    value = *(uint64*)(data + i + 1);
                    value = ntoh64(value);
                    i += 8;
                } else if (31 == lead_value) {
                    handle->temp.indef++;
                    flags = cbor_flag_t::cbor_indef;
                }
            }

            if (cbor_major_t::cbor_major_uint == lead_type) {
                push(handle, lead_type, value, 0);
            } else if (cbor_major_t::cbor_major_nint == lead_type) {
#if defined __SIZEOF_INT128__
                push(handle, lead_type, -((int128)value + 1), 0);
#else
                push(handle, lead_type, -((int64)value + 1), 0);
#endif
            } else if (cbor_major_t::cbor_major_bstr == lead_type) {
                push(handle, lead_type, (byte_t*)data + i + 1, value, flags);
                if (0 == (cbor_flag_t::cbor_indef & flags)) {
                    i += value;
                }
            } else if (cbor_major_t::cbor_major_tstr == lead_type) {
                push(handle, lead_type, (char*)data + i + 1, value, flags);
                if (0 == (cbor_flag_t::cbor_indef & flags)) {
                    i += value;
                }
            } else if (cbor_major_t::cbor_major_array == lead_type) {
                push(handle, lead_type, value, flags);
            } else if (cbor_major_t::cbor_major_map == lead_type) {
                push(handle, lead_type, value, flags);
            } else if (cbor_major_t::cbor_major_tag == lead_type) {
                handle->temp.tag_value = (cbor_tag_t)value;
                continue;
            } else if (cbor_major_t::cbor_major_simple == lead_type) {
                cbor_simple_t simple_type = cbor_simple::is_kind_of(cur);
                switch (simple_type) {
                    case cbor_simple_t::cbor_simple_single_fp:
                        push(handle, lead_type, (float)value, 0);
                        break;
                    case cbor_simple_t::cbor_simple_double_fp:
                        push(handle, lead_type, (double)value, 0);
                        break;
                    default:
                        push(handle, lead_type, value, 0);
                        break;
                }
            }

            handle->temp.tag_value = cbor_tag_t::cbor_tag_unknown;
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t cbor_reader::parse(cbor_reader_context_t* handle, const binary_t& expression) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        ret = parse(handle, &expression[0], expression.size());
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

#if defined __SIZEOF_INT128__
return_t cbor_reader::push(cbor_reader_context_t* handle, uint8 type, int128 data, uint32 flags) {
#else
return_t cbor_reader::push(cbor_reader_context_t* handle, uint8 type, int64 data, uint32 flags) {
#endif
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        if (cbor_major_t::cbor_major_uint == type) {
            cbor_data* temp = nullptr;
            __try_new_catch(temp, new cbor_data(data), ret, __leave2);
            temp->tag(handle->temp.tag_value);
            insert(handle, temp);
        } else if (cbor_major_t::cbor_major_nint == type) {
            cbor_data* temp = nullptr;
            __try_new_catch(temp, new cbor_data(data), ret, __leave2);
            temp->tag(handle->temp.tag_value);
            insert(handle, temp);
        } else if (cbor_major_t::cbor_major_array == type) {
            cbor_array* temp = nullptr;
            __try_new_catch(temp, new cbor_array(flags), ret, __leave2);
            temp->tag(handle->temp.tag_value);
            if (0 == flags) {
                temp->reserve(data);
            }
            insert(handle, temp);
        } else if (cbor_major_t::cbor_major_map == type) {
            cbor_map* temp = nullptr;
            __try_new_catch(temp, new cbor_map(flags), ret, __leave2);
            temp->tag(handle->temp.tag_value);
            if (0 == flags) {
                temp->reserve(data);
            }
            insert(handle, temp);
        } else if (cbor_major_t::cbor_major_tag == type) {
        } else if (cbor_major_t::cbor_major_simple == type) {
            cbor_simple* temp = nullptr;
            __try_new_catch(temp, new cbor_simple(data), ret, __leave2);
            temp->tag(handle->temp.tag_value);
            insert(handle, temp);
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t cbor_reader::push(cbor_reader_context_t* handle, uint8 type, const char* data, size_t size, uint32 flags) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        if (cbor_major_t::cbor_major_tstr == type) {
            if (cbor_flag_t::cbor_indef & flags) {
                cbor_tstrings* temp = nullptr;
                __try_new_catch(temp, new cbor_tstrings(), ret, __leave2);
                insert(handle, temp);
            } else {
                cbor_data* temp = nullptr;
                __try_new_catch(temp, new cbor_data(data, size), ret, __leave2);
                temp->tag(handle->temp.tag_value);
                insert(handle, temp);
            }
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t cbor_reader::push(cbor_reader_context_t* handle, uint8 type, const byte_t* data, size_t size, uint32 flags) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        if (cbor_major_t::cbor_major_bstr == type) {
            if (cbor_flag_t::cbor_indef & flags) {
                cbor_bstrings* temp = nullptr;
                __try_new_catch(temp, new cbor_bstrings(), ret, __leave2);
                insert(handle, temp);
            } else {
                cbor_data* temp = nullptr;
                __try_new_catch(temp, new cbor_data(data, size), ret, __leave2);
                temp->tag(handle->temp.tag_value);
                insert(handle, temp);
            }
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t cbor_reader::push(cbor_reader_context_t* handle, uint8 type, float data, size_t size) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        if (cbor_major_t::cbor_major_float == type) {
            cbor_data* temp = nullptr;
            __try_new_catch(temp, new cbor_data(data), ret, __leave2);
            temp->tag(handle->temp.tag_value);
            insert(handle, temp);
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t cbor_reader::push(cbor_reader_context_t* handle, uint8 type, double data, size_t size) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        if (cbor_major_t::cbor_major_float == type) {
            cbor_data* temp = nullptr;
            __try_new_catch(temp, new cbor_data(data), ret, __leave2);
            temp->tag(handle->temp.tag_value);
            insert(handle, temp);
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t cbor_reader::insert(cbor_reader_context_t* handle, cbor_object* object) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == handle || nullptr == object) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        cbor_object* parent = nullptr;
        if (handle->temp.parents.size()) {
            parent = handle->temp.parents.back();
        }

        cbor_type_t type = object->type();

        if (parent) {
            if (cbor_type_t::cbor_type_map == parent->type()) {
                handle->temp.items.push_back(object);
                if (handle->temp.items.size() >= 2) {
                    cbor_object* lhs = handle->temp.items.at(0);
                    cbor_object* rhs = handle->temp.items.at(1);
                    ret = parent->join(lhs, rhs);
                    if (errorcode_t::success == ret) {
                        handle->temp.items.pop_front();
                        handle->temp.items.pop_front();
                    }
                }
            } else {
                ret = parent->join(object);
            }
        } else {
            handle->roots.push_back(object);
        }

        switch (type) {
            case cbor_type_t::cbor_type_array:
            case cbor_type_t::cbor_type_map:
            case cbor_type_t::cbor_type_bstrs:
            case cbor_type_t::cbor_type_tstrs:
                if (object->capacity() || (cbor_flag_t::cbor_indef & object->get_flags())) {
                    handle->temp.parents.push_back(object);
                }
                break;
            default:
                pop(handle, parent);
                break;
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t cbor_reader::pop(cbor_reader_context_t* handle, cbor_object* object) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == handle || nullptr == object) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        while (object && is_capacity_full(object)) {
            handle->temp.parents.pop_back();

            if (handle->temp.parents.size() > 0) {
                object = handle->temp.parents.back();
            } else {
                break;
            }
        }
    }
    __finally2 {
        // do nothing
    }

    return ret;
}

bool cbor_reader::is_capacity_full(cbor_object* object) {
    bool ret = false;

    if (object) {
        uint32 flags = object->get_flags();
        if (0 == (cbor_flag_t::cbor_indef & flags)) {
            size_t capacity = object->capacity();
            size_t size = object->size();

            if (capacity == size) {
                ret = true;
            }
        }
    }
    return ret;
}

return_t cbor_reader::publish(cbor_reader_context_t* handle, stream_t* stream) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == handle || nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        cbor_publisher publisher;

        publisher.publish(handle, stream);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t cbor_reader::publish(cbor_reader_context_t* handle, binary_t* bin) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == handle || nullptr == bin) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        cbor_publisher publisher;

        publisher.publish(handle, bin);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t cbor_reader::publish(cbor_reader_context_t* handle, cbor_object** root) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == handle || nullptr == root) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        if (handle->roots.size()) {
            cbor_object* object = handle->roots.front();
            object->addref();
            *root = object;
        } else {
            ret = errorcode_t::no_data;
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

template <typename TYPE>
return_t cbor_foreach_t(cbor_reader_context_t* handle, void (*function)(unsigned, cbor_object*, TYPE*), TYPE* param) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        unsigned idx = 0;
        for (cbor_object* object : handle->roots) {
            (*function)(idx, object, param);
            idx++;
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t cbor_reader::cbor_foreach(cbor_reader_context_t* handle, void (*function)(unsigned, cbor_object*, binary_t*), binary_t* param) {
    return cbor_foreach_t<binary_t>(handle, function, param);
}

return_t cbor_reader::cbor_foreach(cbor_reader_context_t* handle, void (*function)(unsigned, cbor_object*, stream_t*), stream_t* param) {
    return cbor_foreach_t<stream_t>(handle, function, param);
}

return_t cbor_parse(cbor_object** object, const binary_t& cbor) {
    return_t ret = errorcode_t::success;
    cbor_reader reader;
    cbor_reader_context_t* reader_context = nullptr;

    __try2 {
        if (nullptr == object) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        if (0 == cbor.size()) {
            ret = errorcode_t::no_data;
            __leave2;
        }

        ret = reader.open(&reader_context);
        if (errorcode_t::success != ret) {
            __leave2;
        }
        ret = reader.parse(reader_context, cbor);
        if (errorcode_t::success != ret) {
            __leave2;
        }
        ret = reader.publish(reader_context, object);
        if (errorcode_t::success != ret) {
            __leave2_trace(ret);
        }
    }
    __finally2 { reader.close(reader_context); }
    return ret;
}

}  // namespace io
}  // namespace hotplace
