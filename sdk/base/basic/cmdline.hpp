/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   cmdline.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 */

#ifndef __HOTPLACE_SDK_BASE_BASIC_CMDLINE__
#define __HOTPLACE_SDK_BASE_BASIC_CMDLINE__

#include <functional>
#include <hotplace/sdk/base/basic/types.hpp>
#include <hotplace/sdk/base/nostd/exception.hpp>
#include <hotplace/sdk/base/string/string.hpp>
#include <iostream>
#include <map>
#include <set>
#include <vector>

namespace hotplace {

enum cmdline_flag_t : uint32 {
    cmdline_preced = (1 << 1),
    cmdline_optional = (1 << 2),
};

template <typename T>
class t_cmdline_t;
/*
 * @brief argument
 * @remarks see t_cmdline_t
 */
template <typename T>
class t_cmdarg_t {
    template <typename>
    friend class t_cmdline_t;

   public:
    template <typename FN>
    t_cmdarg_t(std::string token, std::string desc, FN&& f);
    t_cmdarg_t(const t_cmdarg_t& other) = delete;
    t_cmdarg_t(t_cmdarg_t&& other) = default;  // noexcept = default; GCC 4.8.5 bug
    ~t_cmdarg_t() = default;

    /*
     * @brief key-value pair, next parameter is value
     * @example
     *          -in FILENAME
     *
     *          cmd << t_cmdarg_t<OPTION> ("-in", "input", [](OPTION& o, const char* param) -> void { o.infile = param; }).preced ();
     * @remarks
     *          lvalue reference
     *          rvalue move-chain
     */
    t_cmdarg_t& preced() &;
    t_cmdarg_t&& preced() &&;
    /*
     * @brief optional parameter
     * @remarks
     * @example
     *      -keygen
     *
     *      cmd << t_cmdarg_t<OPTION> ("-keygen", "generate key", [](OPTION& o, const char* param) -> void { o.keygen = true; }).optional ();
     */
    t_cmdarg_t& optional() &;
    t_cmdarg_t&& optional() &&;

    const std::string& token() const;
    const std::string& desc() const;
    uint32 flag() const;

    t_cmdarg_t& operator=(const t_cmdarg_t& other) = delete;
    t_cmdarg_t& operator=(t_cmdarg_t&& other) = default;  // noexcept = default; GCC 4.8.5 bug

   protected:
    return_t bind(T& source, const char* param);

   private:
    std::string _token;
    std::string _desc;
    std::function<void(T&, const char*)> _func;
    uint32 _flags;
};

template <typename T>
template <typename FN>
t_cmdarg_t<T>::t_cmdarg_t(std::string token, std::string desc, FN&& f) : _token(std::move(token)), _desc(std::move(desc)), _func(std::forward<FN>(f)), _flags(0) {}

template <typename T>
t_cmdarg_t<T>& t_cmdarg_t<T>::preced() & {
    _flags |= cmdline_flag_t::cmdline_preced;
    return *this;
}

template <typename T>
t_cmdarg_t<T>&& t_cmdarg_t<T>::preced() && {
    _flags |= cmdline_flag_t::cmdline_preced;
    return std::move(*this);
}

template <typename T>
t_cmdarg_t<T>& t_cmdarg_t<T>::optional() & {
    _flags |= cmdline_flag_t::cmdline_optional;
    return *this;
}

template <typename T>
t_cmdarg_t<T>&& t_cmdarg_t<T>::optional() && {
    _flags |= cmdline_flag_t::cmdline_optional;
    return std::move(*this);
}

template <typename T>
const std::string& t_cmdarg_t<T>::token() const {
    return _token;
}

template <typename T>
const std::string& t_cmdarg_t<T>::desc() const {
    return _desc;
}

template <typename T>
uint32 t_cmdarg_t<T>::flag() const {
    return _flags;
}

template <typename T>
return_t t_cmdarg_t<T>::bind(T& source, const char* param) {
    return_t ret = errorcode_t::success;

    _func(source, param);
    return ret;
}

/*
 * @brief commandline (no thread safe)
 * @example
 *  typedef struct _OPTION {
 *      std::string infile;
 *      std::string outfile;
 *      bool keygen;
 *
 *      _OPTION () : keygen (false) { };
 *  } OPTION;
 *
 *  t_cmdline_t<OPTION> cmdline;
 *
 *  cmdline
 *      << t_cmdarg_t<OPTION> ("-in", "input", [](OPTION& o, const char* param) -> void { o.infile = param; }).preced ()
 *      << t_cmdarg_t<OPTION> ("-out", "output", [](OPTION& o, const char* param) -> void { o.outfile = param; }).preced ()
 *      << t_cmdarg_t<OPTION> ("-keygen", "keygen", [](OPTION& o, const char* param) -> void { o.keygen = true; }).optional ();
 *  ret = cmdline.parse (argc, argv);
 *  if (errorcode_t::success != ret) {
 *      cmdline.help ();
 *  }
 *
 *  const OPTION& opt = cmdline.value ();
 *  std::cout << "infile "  << opt.infile.c_str () << std::endl;
 *  std::cout << "outfile " << opt.outfile.c_str () << std::endl;
 *  std::cout << "keygen "  << opt.keygen << std::endl;
 */
template <typename T>
class t_cmdline_t {
   public:
    t_cmdline_t();
    ~t_cmdline_t();

    /*
     * @brief add handler
     * @param t_cmdarg_t<T> cmd [in]
     */
    t_cmdline_t& operator<<(const t_cmdarg_t<T>& cmd) = delete;
    t_cmdline_t& operator<<(t_cmdarg_t<T>&& cmd);
    /*
     * @brief parse
     * @param int argc [in]
     * @param char** argv [in]
     */
    return_t parse(int argc, char** argv);
    /*
     * @brief return T
     */
    const T& value() const;
    void help() const;

   protected:
   private:
    T _source;
    typedef std::vector<std::string> cmdline_args_list_t;
    typedef std::map<std::string, t_cmdarg_t<T> > cmdline_args_map_t;
    typedef std::set<std::string> cmdline_args_set_t;
    cmdline_args_list_t _list;  // ordered
    cmdline_args_map_t _args;   // arguments
    cmdline_args_set_t _mandatory;
};

template <typename T>
t_cmdline_t<T>::t_cmdline_t() {}

template <typename T>
t_cmdline_t<T>::~t_cmdline_t() {}

template <typename T>
t_cmdline_t<T>& t_cmdline_t<T>::operator<<(t_cmdarg_t<T>&& cmd) {
    std::string token = cmd._token;
    auto pib = _args.emplace(token, std::move(cmd));

    if (pib.second) {
        _list.emplace_back(std::move(token));
    } else {
        throw exception(errorcode_t::duplicate);
    }

    return *this;
}

template <typename T>
return_t t_cmdline_t<T>::parse(int argc, char** argv) {
    return_t ret = errorcode_t::success;
    int index = 0;

    _mandatory.clear();

    for (const auto& pair : _args) {
        const t_cmdarg_t<T>& item = pair.second;
        uint32 flag = item.flag();
        if (0 == (cmdline_flag_t::cmdline_optional & flag)) {
            _mandatory.insert(item.token());
        }
    }

    for (index = 1; index < argc; index++) {
        const char* token = argv[index];
        auto iter = _args.find(token);
        if (_args.end() != iter) {
            if (cmdline_flag_t::cmdline_preced & iter->second.flag()) {  // preced token expect next argument
                if (index + 1 < argc) {
                    char* next_token = argv[index + 1];
                    typename cmdline_args_map_t::iterator check_iter = _args.find(next_token);  // make sure next argument is not token
                    if (check_iter == _args.end()) {
                        iter->second.bind(_source, next_token);  // consume token
                        _mandatory.erase(token);
                        ++index;  // token in the index has been consumed
                    } else {
                        ret = errorcode_t::invalid_parameter;  // -preced parameter waited for an appropriate value, but an argument token appeared
                        break;
                    }
                } else {
                    ret = errorcode_t::invalid_parameter;  // -preced parameter wait for the next token but not found
                    break;
                }
            } else {
                iter->second.bind(_source, "");
                _mandatory.erase(token);
            }
        }
    }

    if (false == _mandatory.empty()) {
        ret = errorcode_t::insufficient;
    }

    return ret;
}

template <typename T>
const T& t_cmdline_t<T>::value() const {
    return _source;
}

template <typename T>
void t_cmdline_t<T>::help() const {
    std::cout << "help" << std::endl;

    size_t maxlen = 5;
    size_t len = 0;
    for (const auto& pair : _args) {
        const auto& item = pair.second;
        len = item.token().size();
        if (len > maxlen) {
            maxlen = len;
        }
    }
    maxlen += 5;  // " arg" for preced case
    std::string fmt;
    fmt = format(ANSI_ESCAPE "%%im%%-%zis" ANSI_ESCAPE "0m %%c %%s\n", maxlen);
    for (const auto& key : _list) {
        auto map_iter = _args.find(key);
        if (_args.end() == map_iter) {
            continue;
        }

        const t_cmdarg_t<T>& item = map_iter->second;
        uint32 flag = item.flag();
        char f = ' ';
        int color = 33;
        if (0 == (cmdline_flag_t::cmdline_optional & flag)) {
            auto set_iter = _mandatory.find(key);
            if (_mandatory.end() == set_iter) {
                f = 'v';
            } else {
                f = '*';
                color = 31;
            }
        }

        constexpr char preced[] = "arg";
        constexpr char nopreced[] = "   ";
        std::string expr_arg = format("%s %s", item.token().c_str(), (cmdline_flag_t::cmdline_preced & flag) ? preced : nopreced);

        printf(fmt.c_str(), color, expr_arg.c_str(), f, item.desc().c_str());
    }
}

}  // namespace hotplace

#endif
