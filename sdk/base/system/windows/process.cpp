/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   process.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/base/stream/types.hpp>
#include <hotplace/sdk/base/system/windows/process.hpp>

namespace hotplace {

process::process() : _pi({0}), _handle(nullptr), _redirection(nullptr) {}

process::~process() {
    if (_pi.hProcess) CloseHandle(_pi.hProcess);
    if (_pi.hThread) CloseHandle(_pi.hThread);
    if (_redirection) delete _redirection;
}

bool process::spawn(const execparam& param) {
    if (_redirection) {
        delete _redirection;
        _redirection = nullptr;
    }
    if (_handle) {
        CloseHandle(_handle);
        _handle = nullptr;
    }
    if (_pi.hThread) {
        CloseHandle(_pi.hThread);
        _pi.hThread = nullptr;
    }

    BOOL ret = FALSE;
    redirection* redir = nullptr;
    __try2 {
        auto build_cmdline = [](const execparam& param) -> std::wstring {
            std::string fullCmd = param.executable;
            for (const auto& arg : param.arguments) {
                fullCmd += " " + arg;
            }
            std::wstring value;
            A2W(value, fullCmd.c_str());
            return value;
        };

        std::wstring cmdLine = build_cmdline(param);

        STARTUPINFOW si = {sizeof(STARTUPINFOW)};
        memset(&_pi, 0, sizeof(_pi));

        SECURITY_ATTRIBUTES sa = {sizeof(SECURITY_ATTRIBUTES), nullptr, TRUE};

        if (param.io_redirection) {
            redir = new redirection;
            if (false == redir->initialize(&sa)) {
                __leave2;
            }

            si.dwFlags |= STARTF_USESTDHANDLES;
            si.hStdInput = redir->get_stdin_read_handle();
            si.hStdOutput = redir->get_stdout_write_handle();
            si.hStdError = redir->get_stdout_write_handle();
        }

        wchar_t* cwd = nullptr;
        std::wstring wCwd;
        if (false == param.workdir.empty()) {
            A2W(wCwd, param.workdir.c_str());

            cwd = (wchar_t*)wCwd.data();
        }

        ret = CreateProcessW(nullptr,                              // application name (use command line)
                             (wchar_t*)cmdLine.data(),             // command line
                             nullptr,                              // process_t handle not inheritable
                             nullptr,                              // thread handle not inheritable
                             param.io_redirection ? TRUE : FALSE,  // set handle inheritance
                             0,                                    // no creation flags
                             nullptr,                              // use parent's environment block
                             cwd,                                  // working directory
                             &si,                                  // pointer to STARTUPINFO
                             &_pi                                  // pointer to PROCESS_INFORMATION
        );

        if (ret) {
            _handle = _pi.hProcess;
            if (_pi.hThread) {
                CloseHandle(_pi.hThread);
                _pi.hThread = nullptr;
            }
            if (redir) {
                redir->event_spawned();
            }
            _redirection = redir;
            redir = nullptr;  // _redirection own redir
        }
    }
    __finally2 {
        if (redir) delete redir;
    }
    return ret;
}

int process::wait() {
    if (nullptr == _handle) return -1;

    WaitForSingleObject(_handle, INFINITE);

    DWORD exitCode = 0;
    GetExitCodeProcess(_handle, &exitCode);
    return static_cast<int>(exitCode);
}

void process::terminate() {
    if (_handle && isrunning()) {
        TerminateProcess(_handle, 1);
    }
}

bool process::isrunning() {
    if (nullptr == _handle) return false;
    DWORD exitCode = 0;
    if (GetExitCodeProcess(_handle, &exitCode)) {
        return exitCode == STILL_ACTIVE;
    }
    return false;
}

redirection_t* process::get_redirection() const { return _redirection; }

}  // namespace hotplace
