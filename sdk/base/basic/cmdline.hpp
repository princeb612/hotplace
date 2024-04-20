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
#include <sdk/base.hpp>
#include <sdk/base/stream.hpp>
#include <set>

namespace hotplace {

enum cmdline_flag_t {
    cmdline_preced = (1 << 1),
    cmdline_optional = (1 << 2),
};

#if __cplusplus >= 201103L  // c++11

template <typename T>
class cmdline_t;
/*
 * @brief argument
 * @remarks see cmdline_t
 */
template <typename T>
class cmdarg_t {
    template <typename>
    friend class cmdline_t;

   public:
    cmdarg_t(std::string token, std::string desc, std::function<void(T&, char*)> f);
    ~cmdarg_t();

    /*
     * @brief key-value pair, next parameter is value
     * @example
     *      -in FILENAME
     *
     *      cmd << cmdarg_t<OPTION> ("-in", "input", [&](OPTION& o, char* param) -> void { o.infile = param; }).preced ();
     */
    cmdarg_t& preced();
    /*
     * @brief optional parameter
     * @remarks
     * @example
     *      -keygen
     *
     *      cmd << cmdarg_t<OPTION> ("-keygen", "generate key", [&](OPTION& o, char* param) -> void { o.keygen = true; }).optional ();
     */
    cmdarg_t& optional();

    const char* token();
    const char* desc();
    uint32 flag();

   protected:
    return_t bind(T& source, char* param);

   private:
    std::string _token;
    std::string _desc;
    std::function<void(T&, char*)> _func;
    uint32 _flag;
};

template <typename T>
cmdarg_t<T>::cmdarg_t(std::string token, std::string desc, std::function<void(T&, char*)> f) : _token(token), _desc(desc), _func(f), _flag(0) {
    // do nothing
}

template <typename T>
cmdarg_t<T>::~cmdarg_t() {
    // do nothing
}

template <typename T>
cmdarg_t<T>& cmdarg_t<T>::preced() {
    _flag |= cmdline_flag_t::cmdline_preced;
    return *this;
}

template <typename T>
cmdarg_t<T>& cmdarg_t<T>::optional() {
    _flag |= cmdline_flag_t::cmdline_optional;
    return *this;
}

template <typename T>
const char* cmdarg_t<T>::token() {
    return _token.c_str();
}

template <typename T>
const char* cmdarg_t<T>::desc() {
    return _desc.c_str();
}

template <typename T>
uint32 cmdarg_t<T>::flag() {
    return _flag;
}

template <typename T>
return_t cmdarg_t<T>::bind(T& source, char* param) {
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
 *  cmdline_t<OPTION> cmdline;
 *
 *  cmdline
 *      << cmdarg_t<OPTION> ("-in", "input", [&](OPTION& o, char* param) -> void { o.infile = param; }).preced ()
 *      << cmdarg_t<OPTION> ("-out", "output", [&](OPTION& o, char* param) -> void { o.outfile = param; }).preced ()
 *      << cmdarg_t<OPTION> ("-keygen", "keygen", [&](OPTION& o, char* param) -> void { o.keygen = true; }).optional ();
 *  ret = cmdline.parse (argc, argv);
 *  if (errorcode_t::success != ret) {
 *      cmdline.help ();
 *  }
 *
 *  OPTION opt = cmdline.value ();
 *  std::cout << "infile "  << opt.infile.c_str () << std::endl;
 *  std::cout << "outfile " << opt.outfile.c_str () << std::endl;
 *  std::cout << "keygen "  << opt.keygen << std::endl;
 */
template <typename T>
class cmdline_t {
   public:
    cmdline_t();
    ~cmdline_t();

    /*
     * @brief add handler
     * @param cmdarg_t<T> cmd [in]
     */
    cmdline_t& operator<<(cmdarg_t<T> cmd);
    /*
     * @brief parse
     * @param int argc [in]
     * @param char** argv [in]
     */
    return_t parse(int argc, char** argv);
    /*
     * @brief return T
     */
    T& value();
    void help();

   protected:
   private:
    T _source;
    typedef std::list<std::string> cmdline_args_list_t;
    typedef std::map<std::string, cmdarg_t<T> > cmdline_args_map_t;
    typedef std::set<std::string> cmdline_args_set_t;
    typedef std::pair<typename cmdline_args_map_t::iterator, bool> cmdline_args_map_pib_t;
    cmdline_args_list_t _list;  // ordered
    cmdline_args_map_t _args;   // arguments
    cmdline_args_set_t _mandatory;
};

template <typename T>
cmdline_t<T>::cmdline_t() {
    // do nothing
}

template <typename T>
cmdline_t<T>::~cmdline_t() {
    // do nothing
}

template <typename T>
cmdline_t<T>& cmdline_t<T>::operator<<(cmdarg_t<T> cmd) {
    int idx = _args.size();

    const char* token = cmd.token();
    cmdline_args_map_pib_t pib = _args.insert(std::make_pair(token, cmd));

    if (pib.second) {
        _list.push_back(token);
    }

    return *this;
}

template <typename T>
return_t cmdline_t<T>::parse(int argc, char** argv) {
    return_t ret = errorcode_t::success;
    int index = 0;

    typename cmdline_args_map_t::iterator iter;

    _mandatory.clear();

    for (iter = _args.begin(); iter != _args.end(); iter++) {
        cmdarg_t<T>& item = iter->second;
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
T& cmdline_t<T>::value() {
    return _source;
}

template <typename T>
void cmdline_t<T>::help() {
    std::cout << "help" << std::endl;

    typename cmdline_args_list_t::iterator list_iter;
    typename cmdline_args_map_t::iterator map_iter;
    typename cmdline_args_set_t::iterator set_iter;

    size_t maxlen = 5;
    size_t len = 0;
    for (map_iter = _args.begin(); map_iter != _args.end(); map_iter++) {
        cmdarg_t<T>& item = map_iter->second;
        len = strlen(item.token());
        if (len > maxlen) {
            maxlen = len;
        }
    }
    maxlen += 5;  // " arg" for preced case
    std::string fmt = format("\e[%%im%%-%zis\e[0m %%c %%s\n", maxlen);
    for (list_iter = _list.begin(); list_iter != _list.end(); list_iter++) {
        std::string& key = *list_iter;

        map_iter = _args.find(key);
        if (_args.end() == map_iter) {
            continue;
        }

        cmdarg_t<T>& item = map_iter->second;
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
        std::string expr_arg = format("%s %s", item.token(), cmdline_flag_t::cmdline_preced & flag ? preced : nopreced);

        printf(fmt.c_str(), color, expr_arg.c_str(), f, item.desc());
    }
}

#endif  // __cplusplus >= 201103L (c++11)

}  // namespace hotplace

#endif
