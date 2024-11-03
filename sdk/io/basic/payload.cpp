/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/io/basic/payload.hpp>
#include <set>

namespace hotplace {
namespace io {

payload::payload() {}

payload::~payload() { clear(); }

payload& payload::operator<<(payload_member* member) {
    if (member) {
        // members
        _members.push_back(member);

        // read(parse)
        if (member->get_name().size()) {
            _members_map.insert(std::make_pair(member->get_name(), member));
        }
    }
    return *this;
}

payload& payload::set_group(const std::string& name, bool optional) {
    _option[name] = optional;
    return *this;
}

bool payload::get_group_condition(const std::string& name) {
    bool ret = true;
    t_maphint<std::string, bool> hint(_option);
    hint.find(name, &ret);
    return ret;
}

payload& payload::set_reference_value(const std::string& name, const std::string& ref) {
    size_t space = 0;
    if (name.size() && ref.size()) {
        payload_member* member_ref = nullptr;
        payload_member* member = nullptr;
        t_maphint<std::string, payload_member*> hint(_members_map);
        hint.find(ref, &member_ref);
        hint.find(name, &member);
        if (member && member_ref) {
            if (member_ref->get_space()) {
                member->set_reference_of(member_ref);
            }
        }
    }
    return *this;
}

return_t payload::write(binary_t& bin) {
    return_t ret = errorcode_t::success;
    for (auto item : _members) {
        bool condition = get_group_condition(item->get_group());
        if (condition) {
            item->write(bin);
        }
    }
    return ret;
}

return_t payload::read(const binary_t& bin) {
    size_t pos = 0;
    return read(bin, pos);
}

return_t payload::read(const byte_t* p, size_t size) {
    size_t pos = 0;
    return read(p, size, pos);
}

return_t payload::read(const binary_t& bin, size_t& pos) { return read((byte_t*)&bin[0], bin.size(), pos); }

return_t payload::read(const byte_t* base, size_t size, size_t& pos) {
    return_t ret = errorcode_t::success;
    size_t size_payload = 0;
    size_t size_estimated = 0;

    __try2 {
        if ((nullptr == base) || (pos > size)) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto lambda_postread = [&](byte_t*& p, size_t& l, size_t itemsize, bool sum) -> void {
            p += itemsize;
            l -= itemsize;
            if (sum) {
                size_payload += itemsize;
            }
        };
        auto lambda_estimate = [&](size_t itemsize) -> void { size_estimated += itemsize; };

        byte_t* baseptr = const_cast<byte_t*>(base);
        size_t size_item = 0;
        std::list<payload_member*> _size_unknown;
        std::set<payload_member*> _once_read;

        lambda_postread(baseptr, size, pos, false);

        {
            byte_t* ptr = baseptr;
            size_t len = size;
            for (auto item : _members) {
                bool condition = get_group_condition(item->get_group());
                if (false == condition) {
                    continue;
                }

                auto try_read = _size_unknown.empty();
                uint16 space = 0;
                if (item->encoded()) {
                    if (try_read) {
                        item->read(ptr, len, &size_item);
                        lambda_postread(ptr, len, size_item, true);
                        lambda_estimate(size_item);
                        _once_read.insert(item);
                    } else {
                        ret = errorcode_t::bad_data;
                        break;
                    }
                } else {
                    space = item->get_space();
                    if (0 == space) {
                        auto ref = item->get_reference_of();
                        if (ref) {
                            space = ref->get_reference_value();
                            item->reserve(space);
                            item->read(ptr, len, &size_item);
                            lambda_postread(ptr, len, size_item, true);
                            lambda_estimate(size_item);
                        } else {
                            _size_unknown.push_back(item);
                        }
                    } else {
                        if (try_read) {
                            item->read(ptr, len, &size_item);
                            lambda_postread(ptr, len, size_item, true);
                            lambda_estimate(size_item);
                            _once_read.insert(item);
                        } else {
                            lambda_estimate(space);
                        }
                    }
                }
            }
        }

        if (size < size_estimated) {
            ret = errorcode_t::bad_data;
        }
        if (errorcode_t::success != ret) {
            __leave2;
        }
        auto state = _size_unknown.size();
        if (0 == state) {
            // nothing to do
            __leave2;
        } else if (1 == state) {
            size_t remain = size - size_estimated;
            payload_member* item = *(_size_unknown.begin());
            item->reserve(remain);
            _size_unknown.clear();

            byte_t* ptr = baseptr;
            size_t len = size;
            for (auto item : _members) {
                bool condition = get_group_condition(item->get_group());
                if (false == condition) {
                    continue;
                }

                auto iter = _once_read.find(item);
                if (_once_read.end() == iter) {
                    // not read yet
                    item->read(ptr, len, &size_item);
                    lambda_postread(ptr, len, size_item, true);
                } else {
                    // once read
                    auto item = *iter;
                    auto space = item->get_space();
                    lambda_postread(ptr, len, space, false);
                }
            }
        } else {  // if (state > 1)
            ret = errorcode_t::bad_data;
            __leave2;
        }
    }
    __finally2 { pos += size_payload; }

    return ret;
}

payload& payload::for_each(std::function<void(payload_member*)> func) {
    if (func) {
        for (auto item : _members) {
            func(item);
        }
    }
    return *this;
}

payload_member* payload::select(const std::string& name) {
    payload_member* item = nullptr;
    t_maphint<std::string, payload_member*> hint(_members_map);
    hint.find(name, &item);
    return item;
}

size_t payload::offset_of(const std::string& name) {
    size_t offset = 0;
    for (auto item : _members) {
        if (name == item->get_name()) {
            break;
        }
        offset += item->get_space();
    }
    return offset;
}

size_t payload::size_estimated() {
    size_t ret_value = 0;
    for (auto item : _members) {
        bool condition = get_group_condition(item->get_group());
        if (false == condition) {
            continue;
        }

        ret_value += item->get_space();
    }
    return ret_value;
}

size_t payload::size_occupied() {
    size_t ret_value = 0;
    for (auto item : _members) {
        bool condition = get_group_condition(item->get_group());
        if (false == condition) {
            continue;
        }

        ret_value += item->get_capacity();
    }
    return ret_value;
}

payload& payload::clear() {
    for (auto item : _members) {
        delete item;
    }
    return *this;
}

size_t payload::size() { return _members.size(); }

}  // namespace io
}  // namespace hotplace
