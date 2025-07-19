/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 * @remarks
 *          RFC 9204 QPACK: Field Compression for HTTP/3
 *
 * Revision History
 * Date         Name                Description
 *
 */

#include "sample.hpp"

unsigned int count_evict_encoder = 0;
unsigned int count_evict_decoder = 0;

void debug_qpack_encoder(trace_category_t, uint32 event) {
    if (trace_event_header_compression_evict == event) {
        count_evict_encoder++;
    }
}
void debug_qpack_decoder(trace_category_t, uint32 event) {
    if (trace_event_header_compression_evict == event) {
        count_evict_decoder++;
    }
}

void test_zero_capacity() {
    _test_case.begin("no dynamic table");
    count_evict_encoder = 0;

    return_t ret = errorcode_t::success;
    qpack_encoder enc;
    qpack_dynamic_table qpack_dyntable;
    binary_t bin;
    uint32 flags = 0;

    // consider no dynamic table
    //  - RFC 9204 5.  Configuration
    //    SETTINGS_QPACK_MAX_TABLE_CAPACITY (0x01):  The default value is zero.

    // debug
    qpack_dyntable.set_debug_hook(debug_qpack_encoder);

    flags = qpack_intermediary | qpack_name_reference;
    enc.insert(&qpack_dyntable, bin, ":authority", "www.example.com", flags);
    enc.insert(&qpack_dyntable, bin, ":path", "/sample/path", flags);
    enc.insert(&qpack_dyntable, bin, "custom-key", "custom-value", flags);
    test_dump(bin, nullptr);
    bin.clear();

    constexpr char expect[] =
        "37 03 63 75 73 74 6F 6D 2D 6B 65 79 0D 63 75 73"  // | 7.custom-key.cus
        "74 6F 6D 2D 76 61 6C 75 65 32 -- -- -- -- -- --"  // | tom-value2
        ;

    enc.insert(&qpack_dyntable, bin, "custom-key", "custom-value2", flags);
    test_expect(bin, expect, __FUNCTION__, nullptr);
    _test_case.assert(0 == qpack_dyntable.get_capacity(), __FUNCTION__, "#capacity %zi", qpack_dyntable.get_capacity());
    _test_case.assert(0 == qpack_dyntable.get_entries(), __FUNCTION__, "#entries %zi", qpack_dyntable.get_entries());
    _test_case.assert(0 == count_evict_encoder, __FUNCTION__, "#eviction check %u", count_evict_encoder);
    _test_case.assert(0 == qpack_dyntable.get_tablesize(), __FUNCTION__, "#table size %zi", qpack_dyntable.get_tablesize());
    bin.clear();
}

void test_tiny_capacity() {
    _test_case.begin("dynamic table capacity 32");
    count_evict_encoder = 0;

    return_t ret = errorcode_t::success;
    qpack_encoder enc;
    qpack_dynamic_table qpack_dyntable;
    binary_t bin;
    uint32 flags = 0;

    // case sizeof_entry(name, value) < qpack_dyntable->get_capacity()
    // insertion impossible
    qpack_dyntable.set_capacity(32);

    // debug
    qpack_dyntable.set_debug_hook(debug_qpack_encoder);

    flags = qpack_intermediary | qpack_name_reference;
    enc.insert(&qpack_dyntable, bin, ":authority", "www.example.com", flags);
    enc.insert(&qpack_dyntable, bin, ":path", "/sample/path", flags);
    enc.insert(&qpack_dyntable, bin, "custom-key", "custom-value", flags);
    enc.insert(&qpack_dyntable, bin, "custom-key", "custom-value2", flags);

    _test_case.assert(32 == qpack_dyntable.get_capacity(), __FUNCTION__, "#capacity %zi", qpack_dyntable.get_capacity());
    _test_case.assert(0 == qpack_dyntable.get_entries(), __FUNCTION__, "#entries %zi", qpack_dyntable.get_entries());
    _test_case.assert(0 == count_evict_encoder, __FUNCTION__, "#eviction check %u", count_evict_encoder);
    _test_case.assert(0 == qpack_dyntable.get_tablesize(), __FUNCTION__, "#table size %zi", qpack_dyntable.get_tablesize());
    _logger->dump(bin);
}

void test_small_capacity() {
    _test_case.begin("dynamic table capacity 80");
    count_evict_encoder = 0;

    return_t ret = errorcode_t::success;
    qpack_encoder enc;
    qpack_dynamic_table qpack_dyntable;
    binary_t bin;
    uint32 flags = qpack_intermediary | qpack_name_reference;

    // assumption - just 1 entry available space
    // always evict older entry while insertion
    qpack_dyntable.set_capacity(80);

    // debug
    qpack_dyntable.set_debug_hook(debug_qpack_encoder);

    auto test = [&](const std::string& name, const std::string& value, unsigned int evict_expect, const char* expect = nullptr) -> void {
        enc.insert(&qpack_dyntable, bin, name, value, flags);
        _test_case.assert(1 == qpack_dyntable.get_entries(), __FUNCTION__, "#entries %zi", qpack_dyntable.get_entries());
        _test_case.assert(evict_expect == count_evict_encoder, __FUNCTION__, "#eviction check %u", count_evict_encoder);
        _test_case.assert((name.size() + value.size() + 32) == qpack_dyntable.get_tablesize(), __FUNCTION__, "#table size %zi", qpack_dyntable.get_tablesize());
        if (expect) {
            _test_case.assert(bin == base16_decode_rfc(expect), __FUNCTION__, "#expect");
        }
        _logger->dump(bin);
        bin.clear();
    };

    test(":authority", "www.example.com", 0);
    test(":path", "/sample/path", 1);
    test("custom-key", "custom-value", 2);

    // literal name representation not name reference
    // no reference 'custom-key' exist
    // constexpr char expect[] =
    //     "4A 63 75 73 74 6F 6D 2D 6B 65 79 0D 63 75 73 74"  // | Jcustom-key.cust
    //     "6F 6D 2D 76 61 6C 75 65 32 -- -- -- -- -- -- --"  // | om-value2
    //     ;
    test("custom-key", "custom-value2", 3);

    _test_case.assert(80 == qpack_dyntable.get_capacity(), __FUNCTION__, "#capacity %zi", qpack_dyntable.get_capacity());
    _logger->dump(bin);
}
