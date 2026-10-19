/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   process.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/base/system/linux/process.hpp>

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <signal.h>
#include <spawn.h>
#include <sys/wait.h>

#include <vector>

extern char** environ;

namespace hotplace {

process::process() : _pid(-1), _exit_code(-1), _is_running(false), _redirection(nullptr) {}

process::~process() {
    if (_redirection) delete _redirection;
}

bool process::spawn(const execparam& param) {
    if (_redirection) {
        delete _redirection;
        _redirection = nullptr;
    }

    posix_spawn_file_actions_t file_actions;
    redirection* redir = nullptr;
    __try2 {
        std::vector<std::string> args;
        args.push_back(param.executable);
        for (const auto& arg : param.arguments) {
            args.push_back(arg);
        }

        std::vector<char*> c_args;
        for (auto& arg : args) {
            c_args.push_back((char*)arg.data());
        }
        c_args.push_back(nullptr);

        posix_spawn_file_actions_init(&file_actions);

        if (param.io_redirection) {
            redir = new redirection;
            if (false == redir->initialize(&file_actions)) {
                __leave2;
            }
        }

#if defined(_GNU_SOURCE) && (__GLIBC__ > 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ >= 29))
        // set working directory if provided (using GNU extension posix_spawn_file_actions_addchdir_np)
        // |Ubuntu                | Ubuntu 18.04 LTS     | glibc 2.27 |
        // |                      | Ubuntu 20.04 LTS     | glibc 2.31 |
        // |                      | Ubuntu 22.04 LTS     | glibc 2.35 |
        // |                      | Ubuntu 24.04 LTS     | glibc 2.39 |
        // |RHEL / CentOS / Rocky | RHEL 6 / CentOS 6    | glibc 2.12 |
        // |                      | RHEL 7 / CentOS 7    | glibc 2.17 |
        // |                      | RHEL 8 / Rocky 8     | glibc 2.28 |
        // |                      | RHEL 9 / Rocky 9     | glibc 2.34 |
        // |                      | RHEL 10              | glibc 2.39 |
        // |Debian                | Debian 9 (Stretch)   | glibc 2.24 |
        // |                      | Debian 10 (Buster)   | glibc 2.28 |
        // |                      | Debian 11 (Bullseye) | glibc 2.31 |
        // |                      | Debian 12 (Bookworm) | glibc 2.36 |
        // |                      | Debian 13 (Trixie)   | glibc 2.41 |
        // |Amazon Linux          | Amazon Linux 1       | glibc 2.17 |
        // |                      | Amazon Linux 2       | glibc 2.26 |
        // |                      | Amazon Linux 2023    | glibc 2.34 |
        if (false == param.workdir.empty()) {
            posix_spawn_file_actions_addchdir_np(&file_actions, param.workdir.c_str());
        }
#endif

        // using default spawn attributes
        int result = posix_spawnp(&_pid, param.executable.c_str(), &file_actions, nullptr, c_args.data(), environ);
        if (0 == result) {
            _is_running = true;
            if (redir) {
                redir->event_spawned();
            }
            _redirection = redir;
            redir = nullptr;  // _redirection own redir
        }
    }
    __finally2 {
        posix_spawn_file_actions_destroy(&file_actions);
        if (redir) delete redir;
    }

    return _is_running;
}

int process::wait() {
    if (false == _is_running) return _exit_code;

    int status = 0;
    pid_t wait_result = waitpid(_pid, &status, 0);
    if (wait_result == _pid) {
        _is_running = false;
        if (_redirection) {
            delete _redirection;
            _redirection = nullptr;
        }
        if (WIFEXITED(status)) {
            _exit_code = WEXITSTATUS(status);
        } else if (WIFSIGNALED(status)) {
            _exit_code = -WIFSIGNALED(status);
        }
    }
    return _exit_code;
}

void process::terminate() {
    if (_is_running && _pid > 0) {
        kill(_pid, SIGKILL);
        wait();
    }
}

bool process::isrunning() {
    if (false == _is_running) return false;

    int status = 0;
    pid_t result = waitpid(_pid, &status, WNOHANG);
    if (result == _pid) {
        _is_running = false;
        if (_redirection) {
            delete _redirection;
            _redirection = nullptr;
        }
        if (WIFEXITED(status)) {
            _exit_code = WEXITSTATUS(status);
        } else if (WIFSIGNALED(status)) {
            _exit_code = -WIFSIGNALED(status);
        }
    }
    return _is_running;
}

redirection_t* process::get_redirection() const { return _redirection; }

}  // namespace hotplace
