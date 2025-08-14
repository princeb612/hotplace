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

#include <functional>
#include <list>
#include <map>
#include <sdk/base/basic/variant.hpp>
#include <sdk/base/nostd/integer.hpp>
#include <sdk/base/system/endian.hpp>
#include <sdk/base/system/shared_instance.hpp>
#include <sdk/base/template.hpp>
#include <sdk/io/basic/types.hpp>
#include <sdk/io/system/types.hpp>
#include <set>

namespace hotplace {
namespace io {

enum payload_member_flag_t : uint8 {
    /**
     * determine following case
     *   pl.reserve("member", 0);
     */
    payload_member_reserve_is_set = 1,
};

/**
 * @brief   payload
 * @sample
 *          // sketch.1
 *          payload pl;
 *          binary_t data = std::move(str2bin("data"));
 *          binary_t pad = std::move(str2bin("pad"));
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
 *          pl.write(bin_padded);
 *          dump_memory(bin_padded, &bs);
 *          printf("%s\n", bs.c_str());
 *          _test_case.assert(12 == bin_padded.size(), __FUNCTION__, "payload padded");  // 3 || "data" || 0x00001000 || "pad"
 *          // 00000000 : 03 64 61 74 61 00 00 10 00 70 61 64 -- -- -- -- | .data....pad
 *
 *          pl.set_group("pad", false); // disable "pad" group
 *          pl.write(bin_notpadded);
 *          dump_memory(bin_notpadded, &bs);
 *          printf("%s\n", bs.c_str());
 *          _test_case.assert(8 == bin_notpadded.size(), __FUNCTION__, "payload not padded");  // "data" || 0x00001000
 *          // 00000000 : 64 61 74 61 00 00 10 00 -- -- -- -- -- -- -- -- | data....
 *
 *          // sketch.2 (parse)
 *          payload pl;
 *          pl << new payload_member(uint8(0), "padlen", "pad")
 *             << new payload_member(binary_t(), "data")
 *             << new payload_member(uint32(0), true, "value")
 *             << new payload_member(binary_t(), "pad", "pad");
 *          binary_t decoded = std::move(base16_decode("036461746100001000706164"));
 *          pl.set_reference_value("pad", "padlen");
 *          pl.read(decoded); // sizeof "pad" refers "padlen" value
 *
 *          binary_t data;
 *          binary_t pad;
 *          auto padlen = pl.t_value_of<uint8>("padlen");
 *          pl.select("data")->get_variant().to_binary(data);
 *          auto value = pl.t_value_of<uint32>("value");
 *          pl.select("pad")->get_variant().to_binary(pad);
 *
 *          // computation
 *          // pl << padlen(uint8:1) << data(unknown:?) << value(uint32:4) << pad(referenceof.padlen:?)
 *          //  input  : 036461746100001000706164
 *          //         : pl << padlen(uint8:1) << data(unknown:?) << value(uint32:4) << pad(referenceof.padlen:?)
 *          //         : pl << padlen(uint8:1) << data(unknown:?) << value(uint32:4) << pad(referenceof.padlen:3)
 *          //  infer  :
 *          //         : 12 - 1 - 4 - 3 = 12 - 8 = 4
 *          //         : pl << padlen(uint8:1) << data(unknown:4) << value(uint32:4) << pad(referenceof.padlen:3)
 *          //         : 03 64617461 00001000 706164
 *          //  result : padlen->3, data->"data", value->0x00001000, pad->"pad"
 */
class payload_member {
   public:
    payload_member(uint8 value, const char* name = nullptr, const char* group = nullptr);
    payload_member(uint8 value, uint16 repeat, const char* name = nullptr, const char* group = nullptr);
    payload_member(uint16 value, bool bigendian, const char* name = nullptr, const char* group = nullptr);
    payload_member(const uint24_t& value, const char* name = nullptr, const char* group = nullptr);
    payload_member(uint32 value, bool bigendian, const char* name = nullptr, const char* group = nullptr);
    payload_member(const uint48_t& value, const char* name = nullptr, const char* group = nullptr);
    payload_member(uint64 value, bool bigendian, const char* name = nullptr, const char* group = nullptr);
#if defined __SIZEOF_INT128__
    payload_member(uint128 value, bool bigendian, const char* name = nullptr, const char* group = nullptr);
#endif
    payload_member(const binary_t& value, const char* name = nullptr, const char* group = nullptr);
    payload_member(const std::string& value, const char* name = nullptr, const char* group = nullptr);
    payload_member(const stream_t* value, const char* name = nullptr, const char* group = nullptr);
    payload_member(payload_encoded* value, const char* name = nullptr, const char* group = nullptr);
    ~payload_member();

    bool get_change_endian();
    std::string get_name() const;
    std::string get_group() const;
    bool encoded() const;  // nullptr != _vl
    payload_member& set_change_endian(bool enable = true);
    payload_member& set_name(const char* name);
    payload_member& set_group(const char* group);

    variant& get_variant();

    size_t get_space();
    size_t get_capacity();
    size_t get_reference_value();
    payload_member* get_reference_of();
    payload_member& set_reference_of(payload_member* member, uint8 multiple = 1);

    payload_member& write(binary_t& bin);
    payload_member& read(const byte_t* ptr, size_t size_ptr, size_t offset, size_t* size_read);
    payload_member& reserve(uint16 size);

    payload_encoded* get_payload_encoded();

    uint8 get_flags();

   protected:
    return_t doread(const byte_t* ptr, size_t size_ptr, size_t offset, size_t* size_read);
    return_t doread_encoded(const byte_t* ptr, size_t size_ptr, size_t offset, size_t* size_read);

   private:
    std::string _name;
    std::string _group;
    bool _bigendian;
    variant _vt;

    payload_member* _ref;
    uint8 _refmulti;
    payload_encoded* _vl;
    uint16 _reserve;
    uint8 _flags;
};

/**
 * @brief   encoded data
 * @sa      quic_encoded
 * @remarks
 *          sketch
 *
 *          std::string data = "data";
 *          binary_t bin_stream = std::move(base16_decode("0x046461746110000102030405060708090a0b0c0d0e0f"));
 *          const byte_t* stream = &bin_stream[0];
 *          size_t streamsize = bin_stream.size();
 *
 *          my_variant_length_data v(data);                 // 04 64 61 74 61 | .data
 *          lsize = v.lsize();                              // 04 -> 1 byte
 *          len = v.value();                                // 04 -> 4
 *          p = v.data();                                   // "data"
 *
 *          lsize = v.lsize(stream, streamsize);            // 04 -> 1 byte
 *          len = v.value(stream, streamsize);              // 04 -> 4
 *          printf("%.*s", (unsigned)len, stream + lsize);  // "data"
 *
 *          stream += len;
 *          streamsize -= len;
 *          lsize = v.lsize(stream, streamsize);            // 10 -> 1 bytes
 *          len = v.value(stream, streamsize);              // 10 -> 16
 *          dump(stream + lsize, len);                      // 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f
 *          p = v.data(stream, streamsize);                 // p = stream + lsize
 */
class payload_encoded {
   public:
    payload_encoded() { _shared.make_share(this); }
    virtual ~payload_encoded() {}

    virtual size_t lsize() = 0;
    virtual size_t value() = 0;
    virtual const byte_t* data() = 0;
    virtual void write(binary_t& target) = 0;

    virtual size_t lsize(const byte_t* stream, size_t size) = 0;
    virtual size_t value(const byte_t* stream, size_t size) = 0;
    virtual return_t read(const byte_t* stream, size_t size, size_t& pos) = 0;
    virtual variant& get_variant() = 0;

    virtual void addref() { _shared.addref(); }
    virtual void release() { _shared.delref(); }

   protected:
   private:
    t_shared_reference<payload_encoded> _shared;
};

class payload {
   public:
    payload();
    ~payload();

    /**
     * @brief   add
     * @sa      payload_member
     */
    payload& operator<<(payload_member* member);

    /**
     * @brief   enable/disable group
     */
    payload& set_group(const std::string& name, bool enable);
    /**
     * @brief   set_group(name, true);
     */
    payload& enable_group(const std::string& name);
    /**
     * @brief   set_group(name, false);
     */
    payload& disable_group(const std::string& name);
    /**
     * @brief   group status
     */
    bool get_group_condition(const std::string& name);
    /**
     * @brief
     * @sample
     *          payload pl;
     *          binary_t data;
     *          binary_t pad;
     *          pl << new payload_member((uint8)0, "padlen", "pad")
     *             << new payload_member(data, "data")
     *             << new payload_member((uint32)0, true, "value")
     *             << new payload_member(pad, "pad", "pad");
     *          binary_t decoded = std::move(base16_decode("036461746100001000706164"));
     *          pl.set_reference_value("pad", "padlen"); // padlen=03, so length of pad 3 bytes
     *          pl.read(decoded);
     * @remarks
     *          case 1 - opaque data;
     *           // stream 05 01 02 03 04 05
     *           //        uint8 len;
     *           //        uint8 data[];
     *           pos = 0;
     *           pl << new payload_member(uint8(0), "len")
     *              << new payload_member(binary_t(), "data");
     *           pl.set_reference_value("data", "len");
     *           pl.read(stream, 6, pos);
     *
     *          case 2
     *           // stream 05 00 01 00 02 00 03 00 04 00 05
     *           //        uint8 len;
     *           //        uint16 data[];
     *           pl << new payload_member(uint8(0), "len")
     *              << new payload_member(binary_t(), "data");
     *           pl.set_reference_value("data", "len", sizeof(uint16));
     *           pos = 0;
     *           pl.read(stream, 11, pos);
     *
     *          case 3
     *           // stream 00 05 00 01 00 02 00 03 00 04 00 05
     *           //        uint16 len;
     *           //        uint16 data[];
     *           pl << new payload_member(uint16(0), true, "len")
     *              << new payload_member(binary_t(), "data");
     *           pl.set_reference_value("data", "len", sizeof(uint16));
     *           pos = 0;
     *           pl.read(stream, 12, pos);
     */
    payload& set_reference_value(const std::string& name, const std::string& ref, uint8 multiple = 1);
    /**
     * @brief   heuristic read
     * @param   const std::string& name [in]
     * @param   std::function<void(payload*, payload_member*)> hook [in]
     * @sample
     *          // sketch
     *
     *          // case.1
     *          // 00000000 : 01 00 05 64 61 74 61 31 00 05 64 61 74 61 32 -- | ...data1..data2
     *          // case.2
     *          // 00000000 : 00 00 05 64 61 74 61 31 -- -- -- -- -- -- -- -- | ...data1
     *
     *          // sample #1
     *          const char* case = "01 00 05 64 61 74 61 31 00 05 64 61 74 61 32";
     *          binary_t bin = std::move(base16_decode_rfc(case));
     *          byte_t* stream = &bin[0];
     *          size_t size = stream.size();
     *          size_t pos = 0;
     *
     *          pl << new payload_member(uint8(0), "hdr")
     *             << new payload_member(uint16(0), true, "len1", "group1")
     *             << new payload_member(binary_t(), "data1", "group1")
     *             << new payload_member(uint16(0), true, "len2", "group2")
     *             << new payload_member(binary_t(), "data2", "group2");
     *          auto lambda = [](payload* pl, payload_member* member) -> void {
     *              // value(hdr)   group2
     *              //     01       enable
     *              //     00       disable
     *              auto hdr = pl->t_value_of<uint8>(member);
     *              pl->set_group ("group2", (0 != hdr));
     *          };
     *          pl.set_condition("hdr", lambda);
     *          pl.read(stream, size, pos);
     *
     *          uint8 hdr = pl.t_value_of<uint8>("hdr");
     *          uint16 len1 = 0;
     *          uint16 len2 = 0;
     *          binary_t data1;
     *          binary_t data2;
     *
     *          len1 = pl.t_value_of<uint16>("len1");
     *          pl.select("data1")->get_variant().to_binary(data1);
     *
     *          bool cond_group2 = pl.get_group_condition("group2");
     *          if (cond_group2) {
     *              len2 = pl.t_value_of<uint16>("len2");
     *              pl.select("data2")->get_variant().to_binary(data2);
     *          }
     *
     *          // sample #2
     *          pl.set_condition("hdr", [](payload* pl, payload_member* item) -> void {
     *              // 7 6 5 4 3 2 1 0
     *              // \ \_ groupB
     *              // \___ groupA
     *              auto val = pl->t_value_of<uint8>(item);
     *              pl->set_group("groupA", (val & 0x80));
     *              pl->set_group("groupB", (val & 0x40));
     *          });
     *          pl.read(stream, size, pos);
     */
    payload& set_condition(const std::string& name, std::function<void(payload*, payload_member*)> hook);

    /**
     * @brief   write
     * @param   binary_t& bin [out]
     */
    return_t write(binary_t& bin);
    /**
     * @param   binary_t& bin [out]
     * @param   const std::set<std::string>& groups [in]
     * @sample
     *
     *          pl.write(bin_nogroup, {});                   // no group
     *          // 00000000 : 01 -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- | .
     *          pl.write(bin_group1, {"group1"});            // no group2
     *          // 00000000 : 00 00 05 64 61 74 61 31 -- -- -- -- -- -- -- -- | ...data1
     *          pl.write(bin_group2, {"group2"});            // no group1
     *          // 00000000 : 00 00 05 64 61 74 61 32 -- -- -- -- -- -- -- -- | ...data2
     *          pl.write(bin_groups, {"group1", "group2"});  // all group
     *          // 00000000 : 01 00 05 64 61 74 61 31 00 05 64 61 74 61 32 -- | ...data1..data2
     */
    return_t write(binary_t& bin, const std::set<std::string>& groups);

    return_t read(const binary_t& bin);
    return_t read(const byte_t* p, size_t size);
    return_t read(const binary_t& bin, size_t& pos);
    return_t read(const byte_t* p, size_t size, size_t& pos);

    payload& for_each(std::function<void(payload_member*)> func);
    payload_member* select(const std::string& name);
    size_t offset_of(const std::string& name);
    size_t numberof_members();

    /**
     * @sample
     *          pl << new payload_member(uint8(), "len")
     *             << new payload_member(binary_t(), "data");
     *          pl.read(stream, size, pos);
     *          auto len = pl.t_value_of<uint8>("len");
     *          auto data = pl.to_bin("data");
     */
    template <typename T>
    T t_value_of(const std::string& name) {
        T i = 0;
        auto item = select(name);
        if (item) {
            if (item->encoded()) {
                auto encoded = item->get_payload_encoded();
                i = encoded->value();
            } else {
                i = t_to_int<T>(item->get_variant());
            }
        }
        return i;
    }
    template <typename T>
    T t_value_of(payload_member* item) {
        T i = 0;
        if (item) {
            if (item->encoded()) {
                auto encoded = item->get_payload_encoded();
                i = encoded->value();
            } else {
                i = t_to_int<T>(item->get_variant());
            }
        }
        return i;
    }
    void get_binary(const std::string& name, binary_t& bin, uint32 flags = 0);
    return_t reserve(const std::string& name, uint16 size);
    size_t get_space(const std::string& name);

   private:
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

    // members
    std::list<payload_member*> _members;  // basic list

    // read(parse)
    std::map<std::string, payload_member*> _members_map;  // search
    std::map<std::string, bool> _option;                  // map<group, true/false>
    struct cond_t {
        std::function<void(payload*, payload_member*)> hook;
    };
    std::multimap<std::string, cond_t> _cond_map;  // std::map<name, cond_t>
};

}  // namespace io
}  // namespace hotplace

#endif
