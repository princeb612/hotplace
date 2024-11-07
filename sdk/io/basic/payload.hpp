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
#include <sdk/base/basic/template.hpp>
#include <sdk/base/basic/variant.hpp>
#include <sdk/base/system/endian.hpp>
#include <sdk/base/template.hpp>
#include <sdk/io/system/types.hpp>

namespace hotplace {
namespace io {

class payload_encoded;

/**
 * @brief   payload
 * @sample
 *          // sketch.1
 *          payload pl;
 *          binary_t data = str2bin("data");
 *          binary_t pad = str2bin("pad");
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
 *          binary_t data;
 *          binary_t pad;
 *          pl << new payload_member((uint8)0, "padlen", "pad")
 *             << new payload_member(data, "data")
 *             << new payload_member((uint32)0, true, "value")
 *             << new payload_member(pad, "pad", "pad");
 *          binary_t decoded = base16_decode("036461746100001000706164");
 *          pl.set_reference_value("pad", "padlen");
 *          pl.read(decoded); // sizeof "pad" refers "padlen" value
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
    payload_member(uint16 value, bool change_endian, const char* name = nullptr, const char* group = nullptr);
    payload_member(uint32_24_t value, const char* name = nullptr, const char* group = nullptr);
    payload_member(uint32 value, bool change_endian, const char* name = nullptr, const char* group = nullptr);
    payload_member(uint64 value, bool change_endian, const char* name = nullptr, const char* group = nullptr);
    payload_member(uint128 value, bool change_endian, const char* name = nullptr, const char* group = nullptr);
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
    payload_member& set_reference_of(payload_member* member);

    payload_member& write(binary_t& bin);
    payload_member& read(const byte_t* ptr, size_t size_ptr, size_t* size_read);
    payload_member& reserve(uint16 size);

    payload_encoded* get_payload_encoded();

   protected:
    return_t doread(const byte_t* ptr, size_t size_ptr, size_t* size_read);
    return_t doread_encoded(const byte_t* ptr, size_t size_ptr, size_t* size_read);

   private:
    std::string _name;
    std::string _group;
    bool _change_endian;
    variant _vt;

    payload_member* _ref;
    payload_encoded* _vl;
    uint16 _reserve;
};

/**
 * @brief   encoded data
 * @sa      quic_integer
 * @remarks
 *          sketch
 *
 *          std::string data = "data";
 *          binary_t bin_stream = base16_decode("0x046461746110000102030405060708090a0b0c0d0e0f");
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

    virtual size_t lsize() = 0;
    virtual size_t value() = 0;
    virtual const byte_t* data() = 0;
    virtual void write(binary_t& target) = 0;

    virtual size_t lsize(const byte_t* stream, size_t size) = 0;
    virtual size_t value(const byte_t* stream, size_t size) = 0;
    virtual void read(const byte_t* stream, size_t size, size_t& pos) = 0;

    virtual void addref() { _shared.addref(); }
    virtual void release() { _shared.delref(); }

   protected:
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
    payload& set_group(const std::string& name, bool optional);
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
     *          pl << new payload_member((uint8)0, "padlen", "pad") << new payload_member(data, "data") << new payload_member((uint32)0, true, "value")
     *             << new payload_member(pad, "pad", "pad");
     *          binary_t decoded = base16_decode("036461746100001000706164");
     *          pl.set_reference_value("pad", "padlen"); // padlen=03, so length of pad 3 bytes
     *          pl.read(decoded);
     */
    payload& set_reference_value(const std::string& name, const std::string& ref);

    return_t write(binary_t& bin);
    return_t read(const binary_t& bin);
    return_t read(const byte_t* p, size_t size);
    return_t read(const binary_t& bin, size_t& pos);
    return_t read(const byte_t* p, size_t size, size_t& pos);

    payload& for_each(std::function<void(payload_member*)> func);
    payload_member* select(const std::string& name);
    size_t offset_of(const std::string& name);
    size_t numberof_members();

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
};

template <typename T>
T t_to_int(payload_member* v) {
    T i = 0;
    if (v) {
        i = t_to_int<T>(v->get_variant());
    }
    return i;
}

}  // namespace io
}  // namespace hotplace

#endif
