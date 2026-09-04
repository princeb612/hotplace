/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   builtinmemory.hpp
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

#ifndef __HOTPLACE_SDK_BASE_BASIC_BUILTINMEMORY__
#define __HOTPLACE_SDK_BASE_BASIC_BUILTINMEMORY__

#include <cstddef>
#include <deque>
#include <hotplace/sdk/base/basic/types.hpp>
#include <hotplace/sdk/base/system/critical_section.hpp>
#include <map>
#include <memory>
#include <set>
#include <unordered_map>

namespace hotplace {

constexpr uint32 BUILTINMEMORY_SIGNATURE = 0x48535548;  // "HUSH" my old ID... I can't use it anymore because require long IDs these days...
constexpr uint32 BUILTINMEMORY_ENTRY_SIGNATURE = 0x19970701;
constexpr uint32 BUILTINMEMORY_CHAIN_SIGNATURE = 0x20091018;
constexpr size_t BUILTINMEMORY_EXPANSION_SIZE = (1 << 20);

enum class builtinpool_policy {
    fixed = 0,      // no additional allocation when memory is exhausted (returns nullptr)
    expandable = 1  // allocate additional pool (segment) when memory is exhausted
};

#pragma pack(push, 8)
union buitinmemory_block_descriptor {
    struct unused_chain {
        uint32 _signature;
        size_t _size;
        union buitinmemory_block_descriptor* _prev;
        union buitinmemory_block_descriptor* _next;
    } chain;

    struct using_entry {
        uint32 _signature;
        size_t _size;
        uint32 _lock;
        struct buitinmemory_context* _parent;
    } entry;
};
#pragma pack(pop)

struct builtinmemory_segment {
    void* _raw_mem{nullptr};
    size_t _size{0};
    builtinmemory_segment* _next{nullptr};
};

struct buitinmemory_context {
    uint32 _signature{0};
    void* _base{nullptr};
    void* _top{nullptr};
    size_t _limit{0};
    buitinmemory_block_descriptor::unused_chain _hint{};
    mutable critical_section _lock;

    builtinpool_policy _policy{builtinpool_policy::fixed};
    size_t _expansion_size{BUILTINMEMORY_EXPANSION_SIZE};  // basic expansion unit
    builtinmemory_segment* _segments{nullptr};

    buitinmemory_context() = default;
    ~buitinmemory_context() = default;

    buitinmemory_context(const buitinmemory_context&) = delete;
    buitinmemory_context& operator=(const buitinmemory_context&) = delete;

    buitinmemory_context(buitinmemory_context&& other) noexcept {
        _signature = other._signature;
        _base = other._base;
        _top = other._top;
        _limit = other._limit;
        _hint = other._hint;
        _policy = other._policy;
        _expansion_size = other._expansion_size;
        _segments = other._segments;
        other._segments = nullptr;
    }

    buitinmemory_context& operator=(buitinmemory_context&& other) noexcept {
        if (this != &other) {
            _signature = other._signature;
            _base = other._base;
            _top = other._top;
            _limit = other._limit;
            _hint = other._hint;
            _policy = other._policy;
            _expansion_size = other._expansion_size;
            _segments = other._segments;
            other._segments = nullptr;
        }
        return *this;
    }
};

class builtinpool {
   public:
    builtinpool() = default;
    builtinpool(void* base, size_t limit, builtinpool_policy policy = builtinpool_policy::fixed, size_t expansion_size = BUILTINMEMORY_EXPANSION_SIZE);
    ~builtinpool();

    builtinpool(const builtinpool&) = delete;
    builtinpool& operator=(const builtinpool&) = delete;

    builtinpool(builtinpool&& other) noexcept;
    builtinpool& operator=(builtinpool&& other) noexcept;

    bool initialize(void* base, size_t limit, builtinpool_policy policy = builtinpool_policy::fixed, size_t expansion_size = BUILTINMEMORY_EXPANSION_SIZE);
    void release();

    void* allocate(size_t demand_size);
    void* reallocate(void* ptr, size_t demand_size);
    void deallocate(void* ptr);

    size_t total_size() const noexcept;
    size_t allocated_size() const noexcept;
    size_t available_size() const noexcept;
    builtinpool_policy get_policy() const noexcept;

   protected:
    static size_t align_up(size_t size, size_t alignment = alignof(std::max_align_t)) noexcept { return (size + alignment - 1) & ~(alignment - 1); }
    bool expand_pool_nolock(size_t min_required_size);
    void clear_segments_nolock();
    bool is_valid_address_range_nolock(const void* ptr, size_t size) const noexcept;

   private:
    buitinmemory_context _context{};
};

// C++ standard allocator adaptor
template <typename T>
class builtinpool_allocator {
   public:
    using value_type = T;

    // 1. default constructor: creates its own expandable builtinpool internally (default size of 1mb)
    builtinpool_allocator() : _pool(std::make_shared<builtinpool>(nullptr, 0, builtinpool_policy::expandable, BUILTINMEMORY_EXPANSION_SIZE)) {}

    // 2. constructor that receives an external pool pointer (also supports the existing pointer reference method)
    explicit builtinpool_allocator(builtinpool* pool) {
        if (nullptr != pool) {
            // create a no-op deleter shared_ptr referencing an external pool
            _pool = std::shared_ptr<builtinpool>(pool, [](builtinpool*) {});
        } else {
            _pool = std::make_shared<builtinpool>(nullptr, 0, builtinpool_policy::expandable, BUILTINMEMORY_EXPANSION_SIZE);
        }
    }

    // 3. allocator copy constructor (shares the same _pool)
    template <typename U>
    builtinpool_allocator(const builtinpool_allocator<U>& other) noexcept : _pool(other._pool) {}

    T* allocate(size_t n) {
        T* ptr = nullptr;

        if (nullptr != _pool) {
            ptr = static_cast<T*>(_pool->allocate(n * sizeof(T)));
        }

        if (nullptr == ptr) {
            throw std::bad_alloc();
        }

        return ptr;
    }

    void deallocate(T* p, size_t n) noexcept {
        if (nullptr != _pool && nullptr != p) {
            _pool->deallocate(p);
        }
    }

    template <typename U>
    bool operator==(const builtinpool_allocator<U>& other) const noexcept {
        return _pool == other._pool;
    }
    template <typename U>
    bool operator!=(const builtinpool_allocator<U>& other) const noexcept {
        return _pool != other._pool;
    }

    // manage built-in/shared memory pools via shared_ptr
    std::shared_ptr<builtinpool> _pool;
};

template <typename T>
using builtinpool_vector = std::vector<T, builtinpool_allocator<T>>;

template <typename T>
using builtinpool_deque = std::deque<T, builtinpool_allocator<T>>;

template <typename T>
using builtinpool_list = std::list<T, builtinpool_allocator<T>>;

template <typename Key, typename Compare = std::less<Key>>
using builtinpool_set = std::set<Key, Compare, builtinpool_allocator<Key>>;

template <typename Key, typename Value, typename Compare = std::less<Key>>
using builtinpool_map = std::map<Key, Value, Compare, builtinpool_allocator<std::pair<const Key, Value>>>;

template <typename Key, typename Value, typename Hash = std::hash<Key>, typename KeyEqual = std::equal_to<Key>>
using builtinpool_unordered_map = std::unordered_map<Key, Value, Hash, KeyEqual, builtinpool_allocator<std::pair<const Key, Value>>>;

template <typename Key, typename Value, typename Compare = std::less<Key>>
using builtinpool_map = std::map<Key, Value, Compare, builtinpool_allocator<std::pair<const Key, Value>>>;

// C++17 PMR (Polymorphic Memory Resource) design pattern
namespace pooled {

/**
 * @brief isolation scope manager using thread-local context
 */
class scope final {
   public:
    explicit scope(builtinpool* pool) noexcept : _prev_pool(get_current_pool()) { get_current_pool() = pool; }

    ~scope() noexcept { get_current_pool() = _prev_pool; }

    scope(const scope&) = delete;
    scope& operator=(const scope&) = delete;

    /**
     * @brief reference to the pool pointer of the currently active scope
     */
    static builtinpool*& get_current_pool() noexcept {
        thread_local builtinpool* tls_pool = nullptr;
        return tls_pool;
    }

   private:
    builtinpool* _prev_pool{nullptr};
};

/**
 * @brief allocator adaptor that automatically receives the builtinpool bound within the scope
 */
template <typename T>
class pooled_allocator : public builtinpool_allocator<T> {
   public:
    using builtinpool_allocator<T>::builtinpool_allocator;

    // by default, the thread_local pool of the current scope is applied first during creation.
    pooled_allocator() : builtinpool_allocator<T>(scope::get_current_pool()) {}

    template <typename U>
    pooled_allocator(const pooled_allocator<U>& other) noexcept : builtinpool_allocator<T>(other) {}
};

template <typename T>
using vector = std::vector<T, pooled_allocator<T>>;

template <typename T>
using deque = std::deque<T, pooled_allocator<T>>;

template <typename T>
using list = std::list<T, pooled_allocator<T>>;

template <typename Key, typename Compare = std::less<Key>>
using set = std::set<Key, Compare, pooled_allocator<Key>>;

template <typename Key, typename Value, typename Compare = std::less<Key>>
using map = std::map<Key, Value, Compare, pooled_allocator<std::pair<const Key, Value>>>;

template <typename Key, typename Value, typename Hash = std::hash<Key>, typename KeyEqual = std::equal_to<Key>>
using unordered_map = std::unordered_map<Key, Value, Hash, KeyEqual, pooled_allocator<std::pair<const Key, Value>>>;

using string = std::basic_string<char, std::char_traits<char>, pooled_allocator<char>>;

}  // namespace pooled

}  // namespace hotplace

#endif
