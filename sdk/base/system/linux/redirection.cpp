/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   redirection.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/base/system/linux/redirection.hpp>

namespace hotplace {

redirection::redirection() : _stdin_pipe(-1), _stdout_pipe(-1) {}

redirection::~redirection() { close(); }

bool redirection::initialize(posix_spawn_file_actions_t* file_actions) {
    int stdin_fds[2] = {-1, -1};
    int stdout_fds[2] = {-1, -1};

    if (pipe(stdin_fds) < 0) return false;
    if (pipe(stdout_fds) < 0) {
        ::close(stdin_fds[0]);
        ::close(stdin_fds[1]);
        return false;
    }

    posix_spawn_file_actions_adddup2(file_actions, stdin_fds[0], STDIN_FILENO);
    posix_spawn_file_actions_addclose(file_actions, stdin_fds[1]);

    posix_spawn_file_actions_adddup2(file_actions, stdout_fds[1], STDOUT_FILENO);
    posix_spawn_file_actions_adddup2(file_actions, stdout_fds[1], STDERR_FILENO);
    posix_spawn_file_actions_addclose(file_actions, stdout_fds[0]);

    _stdin_child_fd = stdin_fds[0];
    _stdout_child_fd = stdout_fds[1];

    _stdin_pipe = stdin_fds[1];
    _stdout_pipe = stdout_fds[0];

    return true;
}

void redirection::event_spawned() {
    if (_stdin_child_fd >= 0) {
        ::close(_stdin_child_fd);
        _stdin_child_fd = -1;
    }
    if (_stdout_child_fd >= 0) {
        ::close(_stdout_child_fd);
        _stdout_child_fd = -1;
    }
}

size_t redirection::read_stdout(void* buffer, size_t size) {
    if (_stdout_pipe < 0) return 0;
    ssize_t bytesRead = read(_stdout_pipe, buffer, size);
    return (bytesRead > 0) ? static_cast<size_t>(bytesRead) : 0;
}

size_t redirection::write_stdin(const void* data, size_t size) {
    if (_stdin_pipe < 0) return 0;
    ssize_t bytesWritten = write(_stdin_pipe, data, size);
    return (bytesWritten > 0) ? static_cast<size_t>(bytesWritten) : 0;
}

void redirection::close() {
    if (_stdin_pipe >= 0) {
        ::close(_stdin_pipe);
        _stdin_pipe = -1;
    }
    if (_stdout_pipe >= 0) {
        ::close(_stdout_pipe);
        _stdout_pipe = -1;
    }
    if (_stdin_child_fd >= 0) {
        ::close(_stdin_child_fd);
        _stdin_child_fd = -1;
    }
    if (_stdout_child_fd >= 0) {
        ::close(_stdout_child_fd);
        _stdout_child_fd = -1;
    }
}

int redirection::get_stdin_handle() const { return _stdin_pipe; }

int redirection::get_stdout_handle() const { return _stdout_pipe; }

}  // namespace hotplace
