/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_IO_BASIC_PAYLOAD__
#define __HOTPLACE_SDK_IO_BASIC_PAYLOAD__

#include <list>
#include <map>
#include <sdk/base.hpp>
#include <sdk/io/system/types.hpp>

namespace hotplace {
namespace io {

/**
 * @brief   payload
 * @sample
 *          // sketch.1
 *          payload pl;
 *          binary_t data = tobin("data");
 *          binary_t pad = tobin("pad");
 *          uint8 padlen = 3;  // "pad"
 *          basic_stream bs;
 *          binary_t bin_padded;
 *          binary_t bin_notpadded;
 *
 *          pl << new payload_member(padlen, "padlen", "pad")
 *             << new payload_member(data, "data")
 *             << new payload_member((uint32)0x1000, true, "value")
 *             << new payload_member(pad, "pad", "pad");
 *
 *          pl.set_group("pad", true); // enable "pad" group
 *          pl.dump(bin_padded);
 *          dump_memory(bin_padded, &bs);
 *          printf("%s\n", bs.c_str());
 *          _test_case.assert(12 == bin_padded.size(), __FUNCTION__, "payload padded");  // 3 || "data" || 0x1000 || "pad"
 *          // 00000000 : 03 64 61 74 61 00 00 10 00 70 61 64 -- -- -- -- | .data....pad
 *
 *          pl.set_group("pad", false); // disable "pad" group
 *          pl.dump(bin_notpadded);
 *          dump_memory(bin_notpadded, &bs);
 *          printf("%s\n", bs.c_str());
 *          _test_case.assert(8 == bin_notpadded.size(), __FUNCTION__, "payload not padded");  // "data" || 0x1000
 *          // 00000000 : 64 61 74 61 00 00 10 00 -- -- -- -- -- -- -- -- | data....
 *
 *          // sketch.2 (parse)
 *          payload pl;
 *          binary_t data;
 *          binary_t pad;
 *          pl << new payload_member((uint8)0, "padlen", "pad")
 *             << new payload_member(data, "data")
 *             << new payload_member((uint32)0, true, "value")
 *             << new payload_member(pad, "pad", "pad");
 *          binary_t decoded = base16_decode("036461746100001000706164");
 *          pl.set_reference_value("pad", "padlen");
 *          pl.read(decoded); // sizeof "pad" refers "padlen" value
 */
class payload_member {
   public:
    payload_member(uint8 value, const char* name = nullptr, const char* group = nullptr);
    payload_member(uint8 value, uint16 repeat, const char* name = nullptr, const char* group = nullptr);
    payload_member(uint16 value, bool change_endian, const char* name = nullptr, const char* group = nullptr);
    payload_member(uint32_24_t value, const char* name = nullptr, const char* group = nullptr);
    payload_member(uint32 value, bool change_endian, const char* name = nullptr, const char* group = nullptr);
    payload_member(uint64 value, bool change_endian, const char* name = nullptr, const char* group = nullptr);
    payload_member(uint128 value, bool change_endian, const char* name = nullptr, const char* group = nullptr);
    payload_member(const binary_t& value, const char* name = nullptr, const char* group = nullptr);

    bool get_change_endian();
    std::string get_name() const;
    std::string get_group() const;
    payload_member& set_change_endian(bool enable = true);
    payload_member& set_name(const char* name);
    payload_member& set_group(const char* group);

    variant& get_variant();

    size_t get_space();
    size_t get_capacity();
    payload_member* get_value_of();
    payload_member& set_value_of(payload_member* member);

    payload_member& dump(binary_t& bin);
    payload_member& read(byte_t* ptr, size_t size_ptr, size_t* size_read);
    payload_member& reserve(uint16 size);

   protected:
   private:
    std::string _name;
    std::string _group;
    bool _change_endian;
    variant _vt;

    payload_member* _member_value_of;
    uint16 _reserve;
};

class payload {
   public:
    payload();
    ~payload();

    payload& operator<<(payload_member* member);

    payload& set_group(const std::string& name, bool optional);
    bool get_group_condition(const std::string& name);
    payload& set_reference_value(const std::string& name, const std::string& ref);

    return_t dump(binary_t& bin);
    return_t read(const binary_t& bin);
    return_t read(byte_t* p, size_t size);

    payload& for_each(std::function<void(payload_member*)> func);
    payload_member* select(const std::string& name);

    /**
     * @brief   size
     * @return  size estimated
     * @remarks
     *          if (stream_size >= pl.size_estimated()) {
     *              pl.read(stream, stream_size);
     *          }
     */
    size_t size_estimated();
    size_t size_occupied();
    payload& clear();

   private:
    // dump
    std::list<payload_member*> _members;  // basic list

    // read(parse)
    std::map<std::string, payload_member*> _members_map;  // search
    std::map<std::string, bool> _option;                  // map<group, true/false>
};

template <typename T>
T t_to_int(payload_member* v) {
    T i = 0;
    if (v) {
        i = t_to_int<T>(v->get_variant().content());
    }
    return i;
}

}  // namespace io
}  // namespace hotplace

#endif
