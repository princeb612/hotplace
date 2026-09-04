/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   builtinmemory.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 * 1997.07.     Soo Han, Kim        created (천리안 프로그래밍 동호회 공개)
 * 2005.        Soo Han, Kim        codename.mirage
 * 2008.06.26   Soo Han, Kim        codename.merlin
 * 2009.10.18   Soo Han, Kim        review,fix (codename.merlin)
 * 2009.11.12   Soo Han, Kim        review,fix (codename.merlin)
 * 2026.09.03   Soo Han and Gemini  refactoring (codename.hotplace)
 *
 */

#include <cassert>
#include <cstring>
#include <hotplace/sdk/base/basic/builtinmemory.hpp>

namespace hotplace {

builtinpool::builtinpool(void* base, size_t limit, builtinpool_policy policy, size_t expansion_size) { initialize(base, limit, policy, expansion_size); }

builtinpool::~builtinpool() { release(); }

builtinpool::builtinpool(builtinpool&& other) noexcept {
    critical_section_guard guard_other(other._context._lock);
    _context = std::move(other._context);
    other._context._signature = 0;
}

builtinpool& builtinpool::operator=(builtinpool&& other) noexcept {
    if (this != &other) {
        critical_section_guard guard_this(_context._lock);
        critical_section_guard guard_other(other._context._lock);

        clear_segments_nolock();

        _context = std::move(other._context);
        other._context._signature = 0;
    }
    return *this;
}

bool builtinpool::initialize(void* base, size_t limit, builtinpool_policy policy, size_t expansion_size) {
    bool result = false;

    __try2 {
        _context._policy = policy;
        _context._expansion_size = expansion_size;

        if (nullptr == base) {
            if (limit < sizeof(buitinmemory_block_descriptor)) {
                limit = expansion_size;
            }
            if (limit < sizeof(buitinmemory_block_descriptor)) {
                __leave2;
            }
            // if base is nullptr, start by dynamically allocating the initial buffer.
            void* new_mem = ::malloc(limit);
            if (nullptr == new_mem) {
                __leave2;
            }

            auto* segment = static_cast<builtinmemory_segment*>(::malloc(sizeof(builtinmemory_segment)));
            if (nullptr == segment) {
                ::free(new_mem);
                __leave2;
            }

            segment->_raw_mem = new_mem;
            segment->_size = limit;
            segment->_next = nullptr;
            _context._segments = segment;

            base = new_mem;
        }

        _context._signature = BUILTINMEMORY_SIGNATURE;
        _context._base = base;
        _context._top = static_cast<char*>(base) + limit;
        _context._limit = limit;

        _context._hint._signature = BUILTINMEMORY_SIGNATURE;
        _context._hint._size = limit;
        _context._hint._prev = nullptr;
        _context._hint._next = static_cast<buitinmemory_block_descriptor*>(base);

        auto* first_block = static_cast<buitinmemory_block_descriptor*>(base);
        first_block->chain._signature = BUILTINMEMORY_CHAIN_SIGNATURE;
        first_block->chain._size = limit;
        first_block->chain._prev = nullptr;
        first_block->chain._next = nullptr;

        result = true;
    }
    __finally2 {}

    return result;
}

void builtinpool::release() {
    critical_section_guard guard_this(_context._lock);

    clear_segments_nolock();

    _context._signature = 0;
    _context._base = nullptr;
    _context._top = nullptr;
    _context._limit = 0;
}

void* builtinpool::allocate(size_t demand_size) {
    void* allocated_ptr = nullptr;

    __try2 {
        if (0 == demand_size || BUILTINMEMORY_SIGNATURE != _context._signature) {
            __leave2;
        }

        demand_size = align_up(demand_size);
        size_t total_demand = demand_size + sizeof(buitinmemory_block_descriptor);

        critical_section_guard guard_this(_context._lock);

    retry_allocation:
        auto* q = reinterpret_cast<buitinmemory_block_descriptor*>(&_context._hint);
        auto* p = q->chain._next;

        while (nullptr != p) {
            if (p->chain._size >= total_demand) {
                if (p->chain._size <= total_demand + sizeof(buitinmemory_block_descriptor)) {
                    q->chain._next = p->chain._next;
                    if (nullptr != p->chain._next) {
                        p->chain._next->chain._prev = (q != reinterpret_cast<buitinmemory_block_descriptor*>(&_context._hint)) ? q : nullptr;
                    }
                    _context._hint._size -= p->chain._size;
                } else {
                    auto* t = reinterpret_cast<buitinmemory_block_descriptor*>(reinterpret_cast<char*>(p) + total_demand);
                    t->chain._size = p->chain._size - total_demand;
                    t->chain._prev = (q != reinterpret_cast<buitinmemory_block_descriptor*>(&_context._hint)) ? q : nullptr;
                    t->chain._next = p->chain._next;
                    t->chain._signature = BUILTINMEMORY_CHAIN_SIGNATURE;

                    q->chain._next = t;
                    if (nullptr != t->chain._next) {
                        t->chain._next->chain._prev = t;
                    }

                    p->entry._size = total_demand;
                    _context._hint._size -= total_demand;
                }

                p->entry._signature = BUILTINMEMORY_ENTRY_SIGNATURE;
                p->entry._parent = &_context;

                if (0 == _context._hint._size) {
                    _context._hint._next = nullptr;
                }

                allocated_ptr = reinterpret_cast<char*>(p) + sizeof(buitinmemory_block_descriptor);
                break;
            }

            q = p;
            p = p->chain._next;
        }

        // attempt additional pool allocation only if the policy is expandable
        if (nullptr == allocated_ptr && builtinpool_policy::expandable == _context._policy) {
            if (false != expand_pool_nolock(total_demand)) {
                goto retry_allocation;
            }
        }
    }
    __finally2 {}

    return allocated_ptr;
}

void builtinpool::deallocate(void* ptr) {
    __try2 {
        if (nullptr == ptr || BUILTINMEMORY_SIGNATURE != _context._signature) {
            __leave2;
        }

        auto* t = reinterpret_cast<buitinmemory_block_descriptor*>(static_cast<char*>(ptr) - sizeof(buitinmemory_block_descriptor));

        if (BUILTINMEMORY_ENTRY_SIGNATURE != t->entry._signature || t->entry._parent != &_context) {
            __leave2;
        }

        critical_section_guard guard_this(_context._lock);

        auto* q = reinterpret_cast<buitinmemory_block_descriptor*>(&_context._hint);

        if (q->chain._next == nullptr) {
            _context._hint._size += t->entry._size;
            t->chain._signature = BUILTINMEMORY_CHAIN_SIGNATURE;
            t->chain._prev = nullptr;
            t->chain._next = nullptr;
            q->chain._next = t;
            __leave2;
        }

        auto* p = q->chain._next;
        while (nullptr != p) {
            if (t < p) {
                _context._hint._size += t->entry._size;
                t->chain._signature = BUILTINMEMORY_CHAIN_SIGNATURE;

                q->chain._next = t;
                t->chain._prev = (q == reinterpret_cast<buitinmemory_block_descriptor*>(&_context._hint)) ? nullptr : q;
                t->chain._next = p;
                p->chain._prev = t;

                auto* w = reinterpret_cast<buitinmemory_block_descriptor*>(reinterpret_cast<char*>(t) + t->chain._size);
                if (w == p && p->chain._signature == BUILTINMEMORY_CHAIN_SIGNATURE) {
                    t->chain._size += p->chain._size;
                    t->chain._next = p->chain._next;
                    if (nullptr != p->chain._next) {
                        p->chain._next->chain._prev = t;
                    }
                }

                if (q != reinterpret_cast<buitinmemory_block_descriptor*>(&_context._hint)) {
                    auto* u = reinterpret_cast<buitinmemory_block_descriptor*>(reinterpret_cast<char*>(q) + q->chain._size);
                    if (u == t) {
                        q->chain._size += t->chain._size;
                        q->chain._next = t->chain._next;
                        if (nullptr != t->chain._next) {
                            t->chain._next->chain._prev = q;
                        }
                    }
                }
                break;
            } else if (p->chain._next == nullptr && p < t) {
                _context._hint._size += t->entry._size;
                t->chain._signature = BUILTINMEMORY_CHAIN_SIGNATURE;
                t->chain._prev = p;
                t->chain._next = nullptr;
                p->chain._next = t;

                auto* u = reinterpret_cast<buitinmemory_block_descriptor*>(reinterpret_cast<char*>(p) + p->chain._size);
                if (u == t) {
                    p->chain._size += t->chain._size;
                    p->chain._next = nullptr;
                }
                break;
            }

            q = p;
            p = p->chain._next;
        }
    }
    __finally2 {}
}

void* builtinpool::reallocate(void* ptr, size_t demand_size) {
    void* result_ptr = nullptr;

    __try2 {
        // case 1: if nullptr == ptr
        if (nullptr == ptr) {
            result_ptr = allocate(demand_size);
            __leave2;
        }

        // case 2: if 0 == demand_size
        if (0 == demand_size) {
            deallocate(ptr);
            __leave2;
        }

        if (BUILTINMEMORY_SIGNATURE != _context._signature) {
            __leave2;
        }

        size_t aligned_demand = align_up(demand_size);
        size_t total_demand = aligned_demand + sizeof(buitinmemory_block_descriptor);

        critical_section_guard guard_this(_context._lock);

        auto* current_block = reinterpret_cast<buitinmemory_block_descriptor*>(static_cast<char*>(ptr) - sizeof(buitinmemory_block_descriptor));

        if (BUILTINMEMORY_ENTRY_SIGNATURE != current_block->entry._signature || current_block->entry._parent != &_context) {
            __leave2;
        }

        size_t current_total_size = current_block->entry._size;
        // size_t current_payload_size = current_total_size - sizeof(buitinmemory_block_descriptor);

        // Case 3: if total_demand == current_total_size
        if (total_demand == current_total_size) {
            result_ptr = ptr;
            __leave2;
        }

        // case 4: shrinking
        if (total_demand < current_total_size) {
            size_t shrink_diff = current_total_size - total_demand;

            // the remaining space must be larger than the descriptor header size to create a new chain
            if (shrink_diff >= sizeof(buitinmemory_block_descriptor)) {
                current_block->entry._size = total_demand;

                auto* split_chain = reinterpret_cast<buitinmemory_block_descriptor*>(reinterpret_cast<char*>(current_block) + total_demand);

                split_chain->chain._signature = BUILTINMEMORY_CHAIN_SIGNATURE;
                split_chain->chain._size = shrink_diff;

                // _hint searching for and inserting at the appropriate position within the list
                auto* q = reinterpret_cast<buitinmemory_block_descriptor*>(&_context._hint);
                auto* p = q->chain._next;

                while (nullptr != p && p < split_chain) {
                    q = p;
                    p = p->chain._next;
                }

                q->chain._next = split_chain;
                split_chain->chain._prev = (q == reinterpret_cast<buitinmemory_block_descriptor*>(&_context._hint)) ? nullptr : q;
                split_chain->chain._next = p;
                if (nullptr != p) {
                    p->chain._prev = split_chain;
                }

                _context._hint._size += shrink_diff;

                // if the next block is a free chain, merge (next merge)
                auto* next_block = reinterpret_cast<buitinmemory_block_descriptor*>(reinterpret_cast<char*>(split_chain) + shrink_diff);

                if (next_block == p && p->chain._signature == BUILTINMEMORY_CHAIN_SIGNATURE) {
                    split_chain->chain._size += p->chain._size;
                    split_chain->chain._next = p->chain._next;
                    if (nullptr != p->chain._next) {
                        p->chain._next->chain._prev = split_chain;
                    }
                }
            }

            result_ptr = ptr;
            __leave2;
        }

        // case 5: in-place expansion
        auto* next_block = reinterpret_cast<buitinmemory_block_descriptor*>(reinterpret_cast<char*>(current_block) + current_total_size);

        // perform full segment area validation instead of a single _top comparison
        bool is_valid_range = is_valid_address_range_nolock(next_block, sizeof(buitinmemory_block_descriptor));
        bool is_next_chain = (false != is_valid_range) && (BUILTINMEMORY_CHAIN_SIGNATURE == next_block->chain._signature);

        if (false != is_next_chain) {
            size_t combined_size = current_total_size + next_block->chain._size;

            if (combined_size >= total_demand) {
                size_t expansion_needed = total_demand - current_total_size;
                size_t remaining_chain_size = next_block->chain._size - expansion_needed;

                // remove the next chain block from the free list link
                auto* prev_chain = next_block->chain._prev;
                auto* next_chain = next_block->chain._next;

                if (nullptr == prev_chain) {
                    _context._hint._next = next_chain;
                } else {
                    prev_chain->chain._next = next_chain;
                }

                if (nullptr != next_chain) {
                    next_chain->chain._prev = prev_chain;
                }

                if (remaining_chain_size >= sizeof(buitinmemory_block_descriptor)) {
                    // register the remaining area as a new free chain
                    auto* new_chain = reinterpret_cast<buitinmemory_block_descriptor*>(reinterpret_cast<char*>(current_block) + total_demand);

                    new_chain->chain._signature = BUILTINMEMORY_CHAIN_SIGNATURE;
                    new_chain->chain._size = remaining_chain_size;
                    new_chain->chain._prev = prev_chain;
                    new_chain->chain._next = next_chain;

                    if (nullptr == prev_chain) {
                        _context._hint._next = new_chain;
                    } else {
                        prev_chain->chain._next = new_chain;
                    }

                    if (nullptr != next_chain) {
                        next_chain->chain._prev = new_chain;
                    }

                    current_block->entry._size = total_demand;
                    _context._hint._size -= expansion_needed;
                } else {
                    // if the remaining area is smaller than the header, it is included entirely in the current block
                    current_block->entry._size = combined_size;
                    _context._hint._size -= next_block->chain._size;
                }

                result_ptr = ptr;
                __leave2;
            }
        }

        // case 6: fallback when in-place expansion is not possible (allocate -> memcpy -> deallocate)
    }
    __finally2 {
        // fallback logic outside lock
        if (nullptr == result_ptr && nullptr != ptr && demand_size > 0) {
            auto* current_block = reinterpret_cast<buitinmemory_block_descriptor*>(static_cast<char*>(ptr) - sizeof(buitinmemory_block_descriptor));
            size_t current_payload_size = current_block->entry._size - sizeof(buitinmemory_block_descriptor);

            result_ptr = allocate(demand_size);
            if (nullptr != result_ptr) {
                std::memcpy(result_ptr, ptr, (demand_size < current_payload_size) ? demand_size : current_payload_size);
                deallocate(ptr);
            }
        }
    }

    return result_ptr;
}

bool builtinpool::expand_pool_nolock(size_t min_required_size) {
    bool result = false;

    __try2 {
        size_t alloc_size = (_context._expansion_size > min_required_size) ? _context._expansion_size : min_required_size;
        alloc_size = align_up(alloc_size);

        // dynamically allocate a new buffer from system/upper memory
        void* new_mem = ::malloc(alloc_size);
        if (nullptr == new_mem) {
            __leave2;
        }

        // segment information recording
        auto* segment = static_cast<builtinmemory_segment*>(::malloc(sizeof(builtinmemory_segment)));
        if (nullptr == segment) {
            ::free(new_mem);
            __leave2;
        }

        segment->_raw_mem = new_mem;
        segment->_size = alloc_size;
        segment->_next = _context._segments;
        _context._segments = segment;

        // set the new area as a descriptor chain and merge it into the free list.
        auto* new_block = static_cast<buitinmemory_block_descriptor*>(new_mem);
        new_block->chain._signature = BUILTINMEMORY_CHAIN_SIGNATURE;
        new_block->chain._size = alloc_size;
        new_block->chain._prev = nullptr;
        new_block->chain._next = nullptr;

        // link to the beginning of the free list (hint chain)
        auto* q = reinterpret_cast<buitinmemory_block_descriptor*>(&_context._hint);
        auto* first = q->chain._next;

        q->chain._next = new_block;
        new_block->chain._prev = nullptr;
        new_block->chain._next = first;

        if (nullptr != first) {
            first->chain._prev = new_block;
        }

        _context._hint._size += alloc_size;
        _context._limit += alloc_size;

        result = true;
    }
    __finally2 {}

    return result;
}

void builtinpool::clear_segments_nolock() {
    builtinmemory_segment* seg = _context._segments;
    while (nullptr != seg) {
        builtinmemory_segment* next = seg->_next;
        if (nullptr != seg->_raw_mem) {
            ::free(seg->_raw_mem);
        }
        ::free(seg);
        seg = next;
    }
    _context._segments = nullptr;
}

bool builtinpool::is_valid_address_range_nolock(const void* ptr, size_t size) const noexcept {
    bool is_valid = false;

    if (nullptr == ptr || 0 == size) {
        return false;
    }

    const char* target_start = static_cast<const char*>(ptr);
    const char* target_end = target_start + size;

    // 1. inspection within the initial base buffer area
    const char* base_start = static_cast<const char*>(_context._base);
    const char* base_end = static_cast<const char*>(_context._top);

    if (target_start >= base_start && target_end <= base_end) {
        is_valid = true;
    } else {
        // 2. check within the dynamic expansion segment list
        builtinmemory_segment* seg = _context._segments;
        while (nullptr != seg) {
            const char* seg_start = static_cast<const char*>(seg->_raw_mem);
            const char* seg_end = seg_start + seg->_size;

            if (target_start >= seg_start && target_end <= seg_end) {
                is_valid = true;
                break;
            }
            seg = seg->_next;
        }
    }

    return is_valid;
}

size_t builtinpool::total_size() const noexcept { return _context._limit; }

size_t builtinpool::allocated_size() const noexcept { return _context._limit - _context._hint._size; }

size_t builtinpool::available_size() const noexcept { return _context._hint._size; }

builtinpool_policy builtinpool::get_policy() const noexcept { return _context._policy; }

}  // namespace hotplace
