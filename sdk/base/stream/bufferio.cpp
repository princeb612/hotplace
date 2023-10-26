/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 * 2008.07.16   Soo Han, Kim        codename.merlin
 * 2023.08.15   Soo Han, Kim        fix : insert (lock)
                                    fix : find_not_first_of, replace
 *                                  removed : replace1
 */

#include <stdlib.h>
#include <string.h>

#include <sdk/base/inline.hpp>
#include <sdk/base/stream/bufferio.hpp>

namespace hotplace {

bufferio::bufferio() {
    // do nothing
}

bufferio::~bufferio() {
    // do nothing
}

return_t bufferio::open(bufferio_context_t** handle, uint32 block_size, byte_t pad_size, uint32 flags) {
    return_t ret = errorcode_t::success;
    bufferio_context_t* context = nullptr;

    __try2 {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        __try_new_catch(context, new bufferio_context_t, ret, __leave2);

        if (0 == block_size) {
            block_size = (1 << 10);
        }

        context->signature = BUFFERIO_CONTEXT_SIGNATURE;
        context->block_size = block_size;
        context->pad_size = pad_size;
        context->flags = flags;

        context->bufferio_size = 0;

        *handle = context;
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

void copy_from_bufferio_queue_nolock(byte_t* dest, size_t& index, bufferin_queue_t& source_queue) {
    bufferio_t* bufferio_item = nullptr;

    for (bufferin_queue_t::iterator it = source_queue.begin(); it != source_queue.end(); it++) {
        bufferio_item = *it;
        memcpy(dest + index, bufferio_item->base_address, bufferio_item->offset);
        index += bufferio_item->offset;
    }
}

void clear_bufferio_queue_nolock(bufferio_context_t* handle, bufferin_queue_t& source_queue) {
    for (bufferin_queue_t::iterator it = source_queue.begin(); it != source_queue.end(); it++) {
        bufferio_t* item = *it;

        if (bufferio_context_flag_t::memzero_free & handle->flags) {
            memset(item->base_address, 0, item->offset);
        }
        free(item->base_address);
        free(item);
    }
    source_queue.clear();
}

return_t bufferio::close(bufferio_context_t* handle) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        if (BUFFERIO_CONTEXT_SIGNATURE != handle->signature) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }

        clear(handle);

        handle->signature = 0;

        delete handle;
    }
    __finally2 {
        // do nothing
    }

    return ret;
}

return_t bufferio::extend(bufferio_context_t* handle, size_t alloc_size, bufferio_t** allocated_pointer, uint32 flag) {
    return_t ret = errorcode_t::success;
    void* memory_allocated = nullptr;
    bufferio_t* bufferio_newly_allocated = nullptr;

    __try2 {
        if (nullptr == handle || nullptr == allocated_pointer) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        if (BUFFERIO_CONTEXT_SIGNATURE != handle->signature) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }

        bufferio_newly_allocated = static_cast<bufferio_t*>(malloc(sizeof(bufferio_t)));
        if (nullptr == bufferio_newly_allocated) {
            ret = errorcode_t::out_of_memory;
            __leave2;
        }

        memory_allocated = malloc(alloc_size + handle->pad_size);
        if (nullptr == memory_allocated) {
            ret = errorcode_t::out_of_memory;
            __leave2;
        }

        bufferio_newly_allocated->limit = alloc_size;
        bufferio_newly_allocated->offset = 0;
        bufferio_newly_allocated->base_address = (byte_t*)memory_allocated;

        memset(memory_allocated, 0, alloc_size + handle->pad_size);

        if (bufferio_flag_t::manual != (flag & bufferio_flag_t::manual)) {
            handle->bufferio_queue.push_back(bufferio_newly_allocated);
        }

        *allocated_pointer = bufferio_newly_allocated;
    }
    __finally2 {
        if (errorcode_t::success != ret) {
            if (nullptr != memory_allocated) {
                free(memory_allocated);
            }
            if (nullptr != bufferio_newly_allocated) {
                free(bufferio_newly_allocated);
            }
        }
    }

    return ret;
}

return_t bufferio::write(bufferio_context_t* handle, const void* data, size_t data_size) {
    return_t ret = errorcode_t::success;
    size_t size_to_copy = 0;
    size_t size_copied = 0;
    size_t size_remained = 0;
    bufferio_t* bufferio_item = nullptr;

    __try2 {
        if (nullptr == handle || nullptr == data) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        if (BUFFERIO_CONTEXT_SIGNATURE != handle->signature) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }

        __try2 {
            handle->bufferio_lock.enter();

            while (data_size > size_copied) {
                if (true == handle->bufferio_queue.empty()) {
                    size_remained = 0;
                } else {
                    bufferin_queue_t::reverse_iterator rit = handle->bufferio_queue.rbegin();
                    bufferio_item = *rit;
                    size_remained = bufferio_item->limit - bufferio_item->offset;
                }

                if (0 == size_remained) {
                    ret = extend(handle, handle->block_size, &bufferio_item);
                    if (errorcode_t::success != ret) {
                        break;
                    }
                    size_remained = handle->block_size;
                }

                size_to_copy = data_size - size_copied;
                if (size_remained >= size_to_copy) {
                    memcpy_inline(bufferio_item->base_address + bufferio_item->offset, bufferio_item->limit - bufferio_item->offset,
                                  (byte_t*)data + size_copied, size_to_copy);
                    bufferio_item->offset += size_to_copy;
                    size_copied += size_to_copy;
                } else {
                    memcpy_inline(bufferio_item->base_address + bufferio_item->offset, bufferio_item->limit - bufferio_item->offset,
                                  (byte_t*)data + size_copied, size_remained);
                    bufferio_item->offset += size_remained;
                    size_copied += size_remained;
                }
            }
        }
        __finally2 {
            handle->bufferio_size += size_copied;

            handle->bufferio_lock.leave();
        }
    }
    __finally2 {
        // do nothing
    }

    return ret;
}

return_t bufferio::clear(bufferio_context_t* handle) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        if (BUFFERIO_CONTEXT_SIGNATURE != handle->signature) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }

        handle->bufferio_lock.enter();
        clear_bufferio_queue_nolock(handle, handle->bufferio_queue);
        handle->bufferio_size = 0;
        handle->bufferio_lock.leave();
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t bufferio::size(bufferio_context_t* handle, size_t* contents_size) {
    return_t ret = errorcode_t::success;
    size_t data_size = 0;

    __try2 {
        if (nullptr == handle || nullptr == contents_size) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        if (BUFFERIO_CONTEXT_SIGNATURE != handle->signature) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }

        data_size = handle->bufferio_size;

        *contents_size = (uint32)data_size;
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t bufferio::get(bufferio_context_t* handle, byte_t** contents, size_t* contents_size, uint32 flags) {
    return_t ret = errorcode_t::success;
    size_t index = 0;
    size_t data_size = 0;
    bufferio_t* bufferio_newly_allocated = nullptr;
    byte_t* data = nullptr;
    uint32 pad_size = 0;

    __try2 {
        if (nullptr == handle || nullptr == contents || nullptr == contents_size) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        if (BUFFERIO_CONTEXT_SIGNATURE != handle->signature) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }

        __try2 {
            handle->bufferio_lock.enter();

            // case1. c_str () after constructor
            // case2. c_str () after clear
            if (0 == handle->bufferio_queue.size() && handle->pad_size) {
                bufferio_t* bufferio_item = nullptr;
                extend(handle, handle->block_size, &bufferio_item);
            }

            data_size = handle->bufferio_size;
            size_t bufferin_queue_size = handle->bufferio_queue.size();
            if (0 == bufferin_queue_size) {
                ret = errorcode_t::no_data;
                *contents = nullptr;
                *contents_size = 0;
                __leave2;
            } else if (1 == bufferin_queue_size) {
                bufferio_t* front = handle->bufferio_queue.front();
                *contents = front->base_address;
                *contents_size = data_size;
            } else {
                pad_size = handle->pad_size;

                ret = extend(handle, data_size, &bufferio_newly_allocated, bufferio_flag_t::manual);
                if (errorcode_t::success != ret) {
                    __leave2;
                }

                data = bufferio_newly_allocated->base_address;

                copy_from_bufferio_queue_nolock(data, index, handle->bufferio_queue);

                memset(data + index, 0, handle->pad_size);

                clear_bufferio_queue_nolock(handle, handle->bufferio_queue);

                bufferio_newly_allocated->offset = data_size;
                handle->bufferio_queue.push_back(bufferio_newly_allocated);

                *contents = data;
                *contents_size = data_size;
            }
        }
        __finally2 { handle->bufferio_lock.leave(); }
    }
    __finally2 {
        // do nothing
    }

    return ret;
}

bool bufferio::compare(bufferio_context_t* handle, const void* data_to_compare, size_t size_to_compare) {
    return_t ret = errorcode_t::success;
    bool ret_bool = false;

    __try2 {
        if (nullptr == handle || nullptr == data_to_compare) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        if (BUFFERIO_CONTEXT_SIGNATURE != handle->signature) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }

        const byte_t* target = static_cast<const byte_t*>(data_to_compare);
        size_t target_index = 0;
        int nCmp = -1;
        size_t dwCompareRemainSize = size_to_compare;
        size_t dwCompareSize = 0;

        handle->bufferio_lock.enter();

        bufferin_queue_t::iterator iter;
        for (iter = handle->bufferio_queue.begin(); iter != handle->bufferio_queue.end() && (dwCompareRemainSize > 0); iter++) {
            bufferio_t* pIo = *iter;

            dwCompareSize = (pIo->offset < dwCompareRemainSize) ? pIo->offset : dwCompareRemainSize;

            nCmp = memcmp(pIo->base_address, target + target_index, dwCompareSize);
            if (0 != nCmp) {
                break;
            }

            target_index += pIo->offset;
            dwCompareRemainSize -= pIo->offset;
        }

        handle->bufferio_lock.leave();

        ret_bool = ((0 == nCmp) && (0 == dwCompareRemainSize));
    }
    __finally2 {
        // do nothing
    }

    return ret_bool;
}

return_t bufferio::cut(bufferio_context_t* handle, uint32 begin_pos, uint32 length) {
    return_t ret = errorcode_t::success;
    uint32 end_pos = begin_pos + length;

    __try2 {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        if (0 == length) {
            __leave2;
        }

        if (BUFFERIO_CONTEXT_SIGNATURE != handle->signature) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }

        if (end_pos > handle->bufferio_size) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        handle->bufferio_lock.enter();

        size_t base = 0;
        size_t limit = 0;

        bufferin_queue_t::iterator iter;
        for (iter = handle->bufferio_queue.begin(); iter != handle->bufferio_queue.end();) {
            bufferio_t* bufferio_item = *iter;

            base = limit;
            limit += bufferio_item->offset;

            if (base > end_pos) {
                break;
            }

            if (limit < begin_pos) {
                iter++;
                continue;
            }

            size_t size_bufferio_previous = 0;
            size_t size_bufferio_next = 0;
            bufferio_t* bufferio_previous = nullptr;
            bufferio_t* bufferio_next = nullptr;

            if (base < begin_pos) {
                size_bufferio_previous = begin_pos - base;

                if (size_bufferio_previous > 0) {
                    extend(handle, size_bufferio_previous, &bufferio_previous, bufferio_flag_t::manual);
                    bufferio_previous->offset = size_bufferio_previous;
                    memcpy(bufferio_previous->base_address, bufferio_item->base_address, size_bufferio_previous);
                }
            }
            if (end_pos < limit) {
                size_bufferio_next = limit - end_pos;

                if (size_bufferio_next > 0) {
                    extend(handle, size_bufferio_next, &bufferio_next, bufferio_flag_t::manual);
                    bufferio_next->offset = size_bufferio_next;
                    memcpy(bufferio_next->base_address, bufferio_item->base_address + (end_pos - base), size_bufferio_next);
                }
            }

            if (nullptr != bufferio_next || nullptr != bufferio_previous) {
                free(bufferio_item->base_address);
                free(bufferio_item);

                handle->bufferio_queue.erase(iter++);

                if (nullptr != bufferio_next) {
                    iter = handle->bufferio_queue.insert(iter, bufferio_next);
                }
                if (nullptr != bufferio_previous) {
                    iter = handle->bufferio_queue.insert(iter, bufferio_previous);
                }
                iter++;
            } else if (begin_pos <= base && limit <= end_pos + handle->pad_size) {
                free(bufferio_item->base_address);
                free(bufferio_item);

                handle->bufferio_queue.erase(iter++);
            } else {
                iter++;
            }
        }

        handle->bufferio_size -= (end_pos - begin_pos);
        handle->bufferio_lock.leave();
    }
    __finally2 {
        // do nothing
    }

    return ret;
}

return_t bufferio::insert(bufferio_context_t* handle, size_t begin_pos, const void* data, size_t data_size) {
    return_t ret = errorcode_t::success;

    __try2 {
        if ((nullptr == handle) || (nullptr == data) || (0 == data_size)) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        if (BUFFERIO_CONTEXT_SIGNATURE != handle->signature) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }

        __try2 {
            handle->bufferio_lock.enter();

            if (handle->bufferio_size < begin_pos) {
                ret = errorcode_t::bad_data;
                __leave2;
            }

            if (handle->bufferio_queue.empty()) {
                write(handle, data, data_size);
            } else {
                size_t base = 0;
                size_t limit = 0;

                bufferin_queue_t::iterator iter;
                for (iter = handle->bufferio_queue.begin(); iter != handle->bufferio_queue.end();) {
                    bufferio_t* bufferio_item = *iter;

                    base = limit;
                    limit += bufferio_item->offset;

                    if (limit < begin_pos) {
                        iter++;
                        continue;
                    }

                    size_t size_bufferio_previous = 0;
                    size_t size_bufferio_next = 0;
                    bufferio_t* bufferio_previous = nullptr;
                    bufferio_t* bufferio_next = nullptr;
                    bufferio_t* bufferio_insert = nullptr;

                    if ((base <= begin_pos) && (begin_pos <= limit)) {
                        size_bufferio_previous = begin_pos - base;

                        if (size_bufferio_previous > 0) {
                            extend(handle, size_bufferio_previous, &bufferio_previous, bufferio_flag_t::manual);
                            bufferio_previous->offset = size_bufferio_previous;
                            memcpy(bufferio_previous->base_address, bufferio_item->base_address, size_bufferio_previous);
                        }

                        extend(handle, data_size, &bufferio_insert, bufferio_flag_t::manual);
                        bufferio_insert->offset = data_size;
                        memcpy(bufferio_insert->base_address, data, data_size);

                        size_bufferio_next = limit - begin_pos;

                        if (size_bufferio_next > 0) {
                            extend(handle, size_bufferio_next, &bufferio_next, bufferio_flag_t::manual);
                            bufferio_next->offset = size_bufferio_next;
                            memcpy(bufferio_next->base_address, bufferio_item->base_address + begin_pos, size_bufferio_next);
                        }
                    }

                    if (nullptr != bufferio_next || nullptr != bufferio_previous) {
                        free(bufferio_item->base_address);
                        free(bufferio_item);

                        handle->bufferio_queue.erase(iter++);

                        if (nullptr != bufferio_next) {
                            iter = handle->bufferio_queue.insert(iter, bufferio_next);
                        }
                        if (nullptr != bufferio_insert) {
                            iter = handle->bufferio_queue.insert(iter, bufferio_insert);
                        }
                        if (nullptr != bufferio_previous) {
                            iter = handle->bufferio_queue.insert(iter, bufferio_previous);
                        }

                        break;
                    } else {
                        iter++;
                    }
                }
            }

            handle->bufferio_size += data_size;
        }
        __finally2 { handle->bufferio_lock.leave(); }
    }
    __finally2 {
        // do nothing
    }

    return ret;
}

return_t bufferio::lock(bufferio_context_t* handle) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        if (BUFFERIO_CONTEXT_SIGNATURE != handle->signature) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }
        handle->bufferio_lock.enter();
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t bufferio::unlock(bufferio_context_t* handle) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        if (BUFFERIO_CONTEXT_SIGNATURE != handle->signature) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }
        handle->bufferio_lock.leave();
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

}  // namespace hotplace
