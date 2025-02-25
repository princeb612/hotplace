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

payload& payload::set_group(const std::string& name, bool enable) {
    _option[name] = enable;
    return *this;
}

bool payload::get_group_condition(const std::string& name) {
    bool ret = true;
    t_maphint<std::string, bool> hint(_option);
    hint.find(name, &ret);
    return ret;
}

payload& payload::set_reference_value(const std::string& name, const std::string& ref, uint8 multiple) {
    size_t space = 0;
    if (name.size() && ref.size()) {
        payload_member* member_ref = nullptr;
        payload_member* member = nullptr;
        t_maphint<std::string, payload_member*> hint(_members_map);
        hint.find(ref, &member_ref);
        hint.find(name, &member);
        if (member && member_ref) {
            if (member_ref->get_space()) {
                member->set_reference_of(member_ref, multiple);
            }
        }
    }
    return *this;
}

payload& payload::set_condition(const std::string& name, std::function<void(payload*, payload_member*)> hook) {
    cond_t cond;
    cond.hook = hook;
    _cond_map.insert({name, cond});
    return *this;
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
    size_t len = 0;
    size_t offset = pos;

    __try2 {
        if (nullptr == base) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        if (pos >= size) {
            ret = errorcode_t::no_data;
            __leave2;
        }

        size_t size_item = 0;
        std::list<payload_member*> list_size_unknown;
        std::set<payload_member*> set_once_read;

        auto lambda_readitem = [&](payload_member* item, const byte_t* ptr, size_t size_ptr, size_t offset, size_t* size_read) -> void {
            item->read(ptr, size_ptr, offset, size_read);
            if (false == _cond_map.empty()) {
                auto const& name = item->get_name();
                auto lbound = _cond_map.lower_bound(name);
                auto ubound = _cond_map.upper_bound(name);
                for (auto iter = lbound; iter != ubound; iter++) {
                    auto cond = iter->second;
                    if (cond.hook) {
                        cond.hook(this, item);
                    }
                }
            }
        };

        for (auto item : _members) {
            bool condition = get_group_condition(item->get_group());
            if (false == condition) {
                continue;
            }

            auto try_read = list_size_unknown.empty();
            uint16 space = 0;
            if (item->encoded()) {
                if (try_read) {
                    lambda_readitem(item, base, size, offset, &size_item);
                    offset += size_item;
                    set_once_read.insert(item);
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
                        lambda_readitem(item, base, size, offset, &size_item);
                        offset += size_item;
                        set_once_read.insert(item);
                    } else {
                        list_size_unknown.push_back(item);
                    }
                } else {
                    if (try_read) {
                        lambda_readitem(item, base, size, offset, &size_item);
                        offset += size_item;
                        set_once_read.insert(item);
                    } else {
                        offset += space;
                    }
                }
            }
            if (errorcode_t::success != ret) {
                break;
            }
        }

        if (errorcode_t::success != ret) {
            __leave2;
        }

        auto state = list_size_unknown.size();
        if (0 == state) {
            // nothing to do
            __leave2;
        } else if (1 == state) {
            size_t remain = size - offset;
            payload_member* item = *(list_size_unknown.begin());
            item->reserve(remain);
            list_size_unknown.clear();
            offset = pos;

            for (auto item : _members) {
                bool condition = get_group_condition(item->get_group());
                if (false == condition) {
                    continue;
                }

                auto iter = set_once_read.find(item);
                if (set_once_read.end() == iter) {
                    // not read yet
                    lambda_readitem(item, base, size, offset, &size_item);
                    offset += size_item;
                } else {
                    // once read
                    auto item = *iter;
                    auto space = item->get_space();
                    offset += space;
                }
            }
        } else {  // if (state > 1)
            ret = errorcode_t::bad_data;
            __leave2;
        }
    }
    __finally2 {
        if (errorcode_t::success == ret) {
            pos = offset;
        }
    }

    return ret;
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

return_t payload::write(binary_t& bin, const std::set<std::string>& groups) {
    return_t ret = errorcode_t::success;
    bool condition = false;
    for (auto item : _members) {
        condition = false;
        auto const& group = item->get_group();
        if (group.empty()) {
            condition = true;
        } else {
            if (false == get_group_condition(group)) {
                continue;
            }

            auto iter = groups.find(group);
            if (groups.end() != iter) {
                condition = true;
            }
        }
        if (condition) {
            item->write(bin);
        }
    }
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
        if (false == get_group_condition(item->get_group())) {
            continue;
        }
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
    _cond_map.clear();
    return *this;
}

size_t payload::numberof_members() { return _members.size(); }

void payload::get_binary(const std::string& name, binary_t& bin, uint32 flags) {
    auto item = select(name);
    if (item) {
        item->get_variant().to_binary(bin, flags);
    }
}

}  // namespace io
}  // namespace hotplace
