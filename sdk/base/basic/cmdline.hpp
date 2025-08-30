/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
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
#include <iostream>
#include <list>
#include <map>
#include <sdk/base/basic/types.hpp>
#include <sdk/base/string/string.hpp>
#include <set>

namespace hotplace {

enum cmdline_flag_t {
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
    t_cmdarg_t(const std::string& token, const std::string& desc, std::function<void(T&, char*)> f);
    t_cmdarg_t(const t_cmdarg_t& rhs);
    t_cmdarg_t(t_cmdarg_t&& rhs);
    ~t_cmdarg_t();

    /*
     * @brief key-value pair, next parameter is value
     * @example
     *      -in FILENAME
     *
     *      cmd << t_cmdarg_t<OPTION> ("-in", "input", [](OPTION& o, char* param) -> void { o.infile = param; }).preced ();
     */
    t_cmdarg_t& preced();
    /*
     * @brief optional parameter
     * @remarks
     * @example
     *      -keygen
     *
     *      cmd << t_cmdarg_t<OPTION> ("-keygen", "generate key", [](OPTION& o, char* param) -> void { o.keygen = true; }).optional ();
     */
    t_cmdarg_t& optional();

    const char* token() const;
    const char* desc() const;
    uint32 flag() const;

   protected:
    return_t bind(T& source, char* param);

   private:
    std::string _token;
    std::string _desc;
    std::function<void(T&, char*)> _func;
    uint32 _flag;
};

template <typename T>
t_cmdarg_t<T>::t_cmdarg_t(const std::string& token, const std::string& desc, std::function<void(T&, char*)> f)
    : _token(token), _desc(desc), _func(f), _flag(0) {}

template <typename T>
t_cmdarg_t<T>::t_cmdarg_t(const t_cmdarg_t& rhs) : _token(rhs._token), _desc(rhs._desc), _func(rhs._func), _flag(rhs._flag) {}

template <typename T>
t_cmdarg_t<T>::t_cmdarg_t(t_cmdarg_t&& rhs) : _token(std::move(rhs._token)), _desc(std::move(rhs._desc)), _func(std::move(rhs._func)), _flag(rhs._flag) {}

template <typename T>
t_cmdarg_t<T>::~t_cmdarg_t() {}

template <typename T>
t_cmdarg_t<T>& t_cmdarg_t<T>::preced() {
    _flag |= cmdline_flag_t::cmdline_preced;
    return *this;
}

template <typename T>
t_cmdarg_t<T>& t_cmdarg_t<T>::optional() {
    _flag |= cmdline_flag_t::cmdline_optional;
    return *this;
}

template <typename T>
const char* t_cmdarg_t<T>::token() const {
    return _token.c_str();
}

template <typename T>
const char* t_cmdarg_t<T>::desc() const {
    return _desc.c_str();
}

template <typename T>
uint32 t_cmdarg_t<T>::flag() const {
    return _flag;
}

template <typename T>
return_t t_cmdarg_t<T>::bind(T& source, char* param) {
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
 *      << t_cmdarg_t<OPTION> ("-in", "input", [](OPTION& o, char* param) -> void { o.infile = param; }).preced ()
 *      << t_cmdarg_t<OPTION> ("-out", "output", [](OPTION& o, char* param) -> void { o.outfile = param; }).preced ()
 *      << t_cmdarg_t<OPTION> ("-keygen", "keygen", [](OPTION& o, char* param) -> void { o.keygen = true; }).optional ();
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
    t_cmdline_t& operator<<(const t_cmdarg_t<T>& cmd);
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
    void help();

   protected:
   private:
    T _source;
    typedef std::list<std::string> cmdline_args_list_t;
    typedef std::map<std::string, t_cmdarg_t<T> > cmdline_args_map_t;
    typedef std::set<std::string> cmdline_args_set_t;
    typedef std::pair<typename cmdline_args_map_t::iterator, bool> cmdline_args_map_pib_t;
    cmdline_args_list_t _list;  // ordered
    cmdline_args_map_t _args;   // arguments
    cmdline_args_set_t _mandatory;
};

template <typename T>
t_cmdline_t<T>::t_cmdline_t() {}

template <typename T>
t_cmdline_t<T>::~t_cmdline_t() {}

template <typename T>
t_cmdline_t<T>& t_cmdline_t<T>::operator<<(const t_cmdarg_t<T>& cmd) {
    int idx = _args.size();

    const char* token = cmd.token();
    cmdline_args_map_pib_t pib = _args.insert(std::make_pair(token, cmd));

    if (pib.second) {
        _list.push_back(token);
    }

    return *this;
}

template <typename T>
t_cmdline_t<T>& t_cmdline_t<T>::operator<<(t_cmdarg_t<T>&& cmd) {
    int idx = _args.size();

    const char* token = cmd.token();
    cmdline_args_map_pib_t pib = _args.insert(std::make_pair(token, cmd));

    if (pib.second) {
        _list.push_back(token);
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

    for (index = 0; index < argc; index++) {
        const char* token = argv[index];
        typename cmdline_args_map_t::iterator iter = _args.find(token);
        if (_args.end() != iter) {
            if (cmdline_flag_t::cmdline_preced & iter->second.flag()) {  // preced token expect next argument
                if (index + 1 < argc) {
                    char* next_token = argv[index + 1];
                    typename cmdline_args_map_t::iterator check_iter = _args.find(next_token);  // make sure next argument is not token
                    if (check_iter == _args.end()) {
                        iter->second.bind(_source, next_token);
                        _mandatory.erase(token);
                    }
                } else {
                    ret = errorcode_t::invalid_parameter;
                    break;
                }
            } else {
                iter->second.bind(_source, (char*)"");
                _mandatory.erase(token);
            }
        }
    }

    if (_mandatory.size()) {
        ret = errorcode_t::insufficient;
    }

    return ret;
}

template <typename T>
const T& t_cmdline_t<T>::value() const {
    return _source;
}

template <typename T>
void t_cmdline_t<T>::help() {
    std::cout << "help" << std::endl;

    typename cmdline_args_map_t::iterator map_iter;
    typename cmdline_args_set_t::iterator set_iter;

    size_t maxlen = 5;
    size_t len = 0;
    for (const auto& pair : _args) {
        const t_cmdarg_t<T>& item = pair.second;
        len = strlen(item.token());
        if (len > maxlen) {
            maxlen = len;
        }
    }
    maxlen += 5;  // " arg" for preced case
    std::string fmt = format("\e[%%im%%-%zis\e[0m %%c %%s\n", maxlen);
    for (const auto& key : _list) {
        map_iter = _args.find(key);
        if (_args.end() == map_iter) {
            continue;
        }

        t_cmdarg_t<T>& item = map_iter->second;
        uint32 flag = item.flag();
        char f = ' ';
        int color = 33;
        if (0 == (cmdline_flag_t::cmdline_optional & flag)) {
            set_iter = _mandatory.find(key);
            if (_mandatory.end() == set_iter) {
                f = 'v';
            } else {
                f = '*';
                color = 31;
            }
        }

        constexpr char preced[] = "arg";
        constexpr char nopreced[] = "   ";
        std::string expr_arg = format("%s %s", item.token(), (cmdline_flag_t::cmdline_preced & flag) ? preced : nopreced);

        printf(fmt.c_str(), color, expr_arg.c_str(), f, item.desc());
    }
}

}  // namespace hotplace

#endif
