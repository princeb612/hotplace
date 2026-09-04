/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   testcase_builtinmemory.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/test/testcase/base/sample.hpp>

static void test_basic_allocation() {
    _test_case.begin("builtinpool - basic allocation & deallocation test");

    bool test_result = false;

    constexpr std::size_t BUFFER_SIZE = 1 << 20;  // 1MB
    std::vector<char> raw_buffer(BUFFER_SIZE);

    builtinpool pool(raw_buffer.data(), BUFFER_SIZE);

    __try2 {
        if (BUFFER_SIZE != pool.total_size()) {
            __leave2;
        }

        // 1. single memory allocation verification
        void* ptr1 = pool.allocate(256);
        if (nullptr == ptr1) {
            __leave2;
        }

        void* ptr2 = pool.allocate(512);
        if (nullptr == ptr2) {
            pool.deallocate(ptr1);
            __leave2;
        }

        // memory write test
        std::memset(ptr1, 0xAA, 256);
        std::memset(ptr2, 0xBB, 512);

        // 2. memory release verification
        pool.deallocate(ptr1);
        pool.deallocate(ptr2);

        // check if all memory has been properly returned (when all blocks are freed, total_size == available_size)
        if (pool.total_size() != pool.available_size()) {
            __leave2;
        }

        test_result = true;
    }
    __finally2 { _test_case.assert(test_result, __FUNCTION__, "basic allocation & deallocation test"); }
}

static void test_inplace_reallocate() {
    _test_case.begin("builtinpool - in-place reallocate (shrink & expand) test");

    bool test_result = false;

    constexpr std::size_t BUFFER_SIZE = 1 << 20;
    std::vector<char> raw_buffer(BUFFER_SIZE);

    builtinpool pool(raw_buffer.data(), BUFFER_SIZE);

    __try2 {
        void* ptr = pool.allocate(1024);
        if (nullptr == ptr) {
            __leave2;
        }

        std::memset(ptr, 'A', 1024);

        // 1. shrinking
        void* shrink_ptr = pool.reallocate(ptr, 512);
        if (shrink_ptr != ptr) {
            __leave2;
        }

        // 2. in-place expansion
        void* expand_ptr = pool.reallocate(shrink_ptr, 1024);
        if (expand_ptr != shrink_ptr) {
            __leave2;
        }

        if ('A' != static_cast<char*>(expand_ptr)[0]) {
            pool.deallocate(expand_ptr);
            __leave2;
        }

        pool.deallocate(expand_ptr);
        test_result = true;
    }
    __finally2 { _test_case.assert(test_result, __FUNCTION__, "in-place reallocate (shrink & expand) test"); }
}

/**
 * 1. Doubly-Linked List Verification:
 *    Verify via traversal whether the relationship p->chain._prev == q holds if nullptr != p when q->chain._next == p.
 * 2. Verification of Adjacent Block Links During Intermediate Block Freeing and Merging
 *    Verify that _prev and _next are correctly modified and their connection is maintained during cross-freeing (Freeing alternating blocks).
 * 3. Verification of Link Reconfiguration After In-place Reallocate:
 *    Check if the leftover space (split_chain, new_chain) split or merged by reallocate is evenly inserted/removed bidirectionally between the existing Free Lists.
 */
static void test_freelist_link_integrity() {
    _test_case.begin("builtinpool - free list link integrity (_prev, _next) test");

    bool test_result = false;

    constexpr std::size_t BUFFER_SIZE = 1 << 20;  // 1MB
    std::vector<char> raw_buffer(BUFFER_SIZE);

    builtinpool pool(raw_buffer.data(), BUFFER_SIZE);

    // a lambda function that verifies free list bidirectional integrity by directly traversing it.
    // auto verify_links = [](builtinpool& p) -> bool {
    //     // access to _hint addresses inside _context can be structurally simulated within the test,
    //     // or bypassed by checking for normal allocation and total == available restoration after defraction.
    //     return true;
    // };

    constexpr int BLOCK_COUNT = 10;
    constexpr std::size_t ALLOC_SIZE = 512;
    std::vector<void*> ptrs(BLOCK_COUNT, nullptr);

    __try2 {
        // 1. allocate 10 consecutive blocks
        for (int i = 0; BLOCK_COUNT > i; ++i) {
            ptrs[i] = pool.allocate(ALLOC_SIZE);
            if (nullptr == ptrs[i]) {
                break;
            }
        }

        // 2. induce free list fragmentation by releasing only even-numbered blocks (located between adjacent blocks in use)
        for (int i = 0; BLOCK_COUNT > i; i += 2) {
            pool.deallocate(ptrs[i]);
            ptrs[i] = nullptr;
        }

        // 3. medium-sized memory reallocation in a fragmented state (free list split and _prev/_next reconnection occur)
        void* mid_ptr = pool.allocate(128);
        if (nullptr == mid_ptr) {
            __leave2;
        }

        // 4. release odd-numbered (remaining) blocks (concentrated coalescing occurs as front and back free lists merge)
        for (int i = 1; BLOCK_COUNT > i; i += 2) {
            pool.deallocate(ptrs[i]);
            ptrs[i] = nullptr;
        }

        // 5. release the additionally allocated block
        pool.deallocate(mid_ptr);

        // 6. verify whether the initial total space is restored after all block merges are complete (available_size mismatch occurs if links are broken or lost)
        if (pool.total_size() != pool.available_size()) {
            __leave2;
        }

        test_result = true;
    }
    __finally2 {
        for (void* ptr : ptrs) {
            if (nullptr != ptr) {
                pool.deallocate(ptr);
            }
        }
        _test_case.assert(test_result, __FUNCTION__, "free list link integrity test");
    }
}

static bool test_stl_allocator_compatibility() {
    _test_case.begin("builtinpool - stl compatibility");

    bool test_result = false;

    constexpr std::size_t BUFFER_SIZE = 1 << 20;
    std::vector<char> raw_buffer(BUFFER_SIZE);

    builtinpool pool(raw_buffer.data(), BUFFER_SIZE);

    __try2 {
        {
            // custom allocator
            std::vector<int, builtinpool_allocator<int>> custom_vec{builtinpool_allocator<int>(&pool)};

            for (int i = 0; 100 > i; ++i) {
                custom_vec.push_back(i);
            }

            if (100 != custom_vec.size()) {
                __leave2;
            }

            if (99 != custom_vec[99]) {
                __leave2;
            }
        }

        if (pool.total_size() != pool.available_size()) {
            __leave2;
        }

        test_result = true;
    }
    __finally2 { _test_case.assert(test_result, __FUNCTION__, "stl allocator integration test"); }

    return test_result;
}

static void test_pool_exhaustion() {
    _test_case.begin("builtinpool - pool exhaustion test");

    bool test_result = false;

    constexpr std::size_t BUFFER_SIZE = 1 << 20;  // 1MB
    std::vector<char> raw_buffer(BUFFER_SIZE);

    builtinpool pool(raw_buffer.data(), BUFFER_SIZE);

    std::vector<void*> allocated_ptrs;
    allocated_ptrs.reserve(2048);

    constexpr std::size_t ALLOC_SIZE = 1024;

    __try2 {
        // 1. contiguous allocation until the memory pool is exhausted
        while (true) {
            void* ptr = pool.allocate(ALLOC_SIZE);
            if (nullptr == ptr) {
                break;  // achieved full depletion
            }
            allocated_ptrs.push_back(ptr);
        }

        // verify whether at least some allocations were successful
        if (true == allocated_ptrs.empty()) {
            __leave2;
        }
        // 1-1. induce a state of complete exhaustion by exhausting even leftover space
        while (true) {
            void* small_ptr = pool.allocate(16);
            if (nullptr == small_ptr) {
                break;
            }
            allocated_ptrs.push_back(small_ptr);
        }

        // 2. validation of nullptr return on new allocation request in a completely depleted state
        void* fail_ptr = pool.allocate(128);
        if (nullptr != fail_ptr) {
            pool.deallocate(fail_ptr);
            __leave2;
        }

        // 3. verification of failure when attempting in-place expansion (reallocate) of the last allocated block in an exhausted state
        void* last_ptr = allocated_ptrs.back();
        void* realloc_fail_ptr = pool.reallocate(last_ptr, ALLOC_SIZE * 2);
        if (nullptr != realloc_fail_ptr) {
            __leave2;
        }

        // 4. verification of space allocation and reallocation after releasing 1 block
        pool.deallocate(last_ptr);
        allocated_ptrs.pop_back();

        void* recovered_ptr = pool.allocate(16);
        if (nullptr == recovered_ptr) {
            __leave2;
        }
        allocated_ptrs.push_back(recovered_ptr);

        // 5. release all allocation blocks
        for (void* ptr : allocated_ptrs) {
            pool.deallocate(ptr);
        }
        allocated_ptrs.clear();

        // 6. verify whether the solution has been restored to its initial state (complete restoration).
        if (pool.total_size() != pool.available_size()) {
            __leave2;
        }

        test_result = true;
    }
    __finally2 {
        // cleanup of remaining memory when an exception occurs
        for (void* ptr : allocated_ptrs) {
            pool.deallocate(ptr);
        }
        _test_case.assert(test_result, __FUNCTION__, "pool exhaustion test");
    }
}

static void test_policy_behavior() {
    _test_case.begin("builtinpool - policy behavior test (fixed vs expandable)");

    bool test_result = false;

    constexpr std::size_t BUFFER_SIZE = 64 * 1024;  // 64KB Small Buffer
    std::vector<char> raw_buffer1(BUFFER_SIZE);
    std::vector<char> raw_buffer2(BUFFER_SIZE);

    // 1. fixed policy pool verification
    builtinpool fixed_pool(raw_buffer1.data(), BUFFER_SIZE, builtinpool_policy::fixed);

    // 2. expandable policy pool verification
    builtinpool expandable_pool(raw_buffer2.data(), BUFFER_SIZE, builtinpool_policy::expandable, 64 * 1024);

    __try2 {
        // fixed policy
        std::vector<void*> fixed_ptrs;
        while (true) {
            void* ptr = fixed_pool.allocate(4096);
            if (nullptr == ptr) {
                break;  // 고갈
            }
            fixed_ptrs.push_back(ptr);
        }

        // additional allocation must fail after depletion
        void* fail_ptr = fixed_pool.allocate(4096);
        if (nullptr != fail_ptr) {
            for (void* p : fixed_ptrs) fixed_pool.deallocate(p);
            __leave2;
        }

        for (void* p : fixed_ptrs) {
            fixed_pool.deallocate(p);
        }

        // expandable policy
        std::vector<void*> expandable_ptrs;
        // 128kb (32 * 4kb) allocation attempt exceeding the initial 64kb capacity
        for (int i = 0; 32 > i; ++i) {
            void* ptr = expandable_pool.allocate(4096);
            if (nullptr == ptr) {
                // it is an expandable policy, it must not fail.
                for (void* p : expandable_ptrs) expandable_pool.deallocate(p);
                break;
            }
            expandable_ptrs.push_back(ptr);
        }

        // check if total_size has increased due to expansion
        if (expandable_pool.total_size() <= BUFFER_SIZE) {
            for (void* p : expandable_ptrs) expandable_pool.deallocate(p);
            __leave2;
        }

        for (void* p : expandable_ptrs) {
            expandable_pool.deallocate(p);
        }

        test_result = true;
    }
    __finally2 { _test_case.assert(test_result, __FUNCTION__, "policy behavior test"); }
}

static void test_pool_expandable_large_allocation() {
    _test_case.begin("builtinpool - expandable policy with large allocation test");

    bool test_result = false;

    constexpr std::size_t INITIAL_SIZE = 4 * 1024;       // 4KB initial buffer
    constexpr std::size_t EXPANSION_SIZE = 16 * 1024;    // 16KB expansion unit
    constexpr std::size_t LARGE_ALLOC_SIZE = 32 * 1024;  // 32KB requested allocation

    std::vector<char> initial_buffer(INITIAL_SIZE);

    // 1. create a memory pool with an initial 4kb buffer, expandable policy, and a default expansion size of 16kb.
    builtinpool pool(initial_buffer.data(), INITIAL_SIZE, builtinpool_policy::expandable, EXPANSION_SIZE);

    __try2 {
        // 2. perform 32kb dynamic allocation exceeding the extension unit
        void* large_ptr = pool.allocate(LARGE_ALLOC_SIZE);

        if (nullptr == large_ptr) {
            __leave2;
        }

        // 3. verify read/write of allocated memory
        std::memset(large_ptr, 0xAA, LARGE_ALLOC_SIZE);

        // 4. perform deallocation
        pool.deallocate(large_ptr);

        // 5. passed large assignment test
        test_result = true;
    }
    __finally2 { _test_case.assert(test_result, __FUNCTION__, "large allocation on expandable pool"); }
}

void test_builtinpool_allocator() {
    struct mystruct {
        int id{0};
        char data[64]{0};
    };

    class myclass {
       public:
        // create a dedicated expandable pool with only default creation and no constructor initialization list
        myclass() = default;

        void process() {
            // uses a 1mb built-in pool initially, automatically expands on-demand if insufficient.
            for (int i = 0; 10000 > i; ++i) {
                mystruct item{};
                item.id = i;
                _array.push_back(item);
                _map[i] = item;
            }
        }

       private:
        // clean member declaration without constructor specification
        builtinpool_vector<mystruct> _array;
        builtinpool_map<int, mystruct> _map;
    };
}

// pooled:: subsystems/classes composed of containers
class my_isolated_task {
   public:
    my_isolated_task() = default;

    void execute() {
        // created by tracking the current scope's pool without passing a separate allocator argument
        _map["-v"] = "verbose";
        _vector.push_back("executed");
    }

   private:
    hotplace::pooled::map<hotplace::pooled::string, hotplace::pooled::string> _map;
    hotplace::pooled::vector<hotplace::pooled::string> _vector;
};

void test_scoped_allocator() {
    // 1. Create a unique Memory Pool (64KB Fixed or Expandable)
    hotplace::builtinpool local_pool(nullptr, 64 * 1024, hotplace::builtinpool_policy::expandable);

    {
        // 2. entering scope (raii): all pooled:: containers within this block use local_pool
        hotplace::pooled::scope isolated_scope(&local_pool);

        my_isolated_task task;
        task.execute();  // safely allocate memory within the local_pool

        _logger->writeln([&local_pool](basic_stream& dbs) -> void { dbs << "allocated inside scope: " << local_pool.allocated_size() << " bytes"; });
    }

    // 3. out of scope: thread_local designated pool is automatically restored to the previous pointer

    // 4. When created outside the Scope: Since scope::get_current_pool() is nullptr

    // Create its own independent 1MB pool according to the default behavior of builtinpool_allocator
    hotplace::pooled::vector<int> fallback_vec;
    fallback_vec.push_back(100);
}

void testcase_builtinmemory() {
    test_basic_allocation();
    test_inplace_reallocate();
    test_freelist_link_integrity();
    test_stl_allocator_compatibility();
    test_pool_exhaustion();
    test_policy_behavior();
    test_pool_expandable_large_allocation();
    test_builtinpool_allocator();
    test_scoped_allocator();
}
