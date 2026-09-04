#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../header/helper.h"

bool is_file(const char *path)
{
    struct stat attributes;

    return path != NULL && stat(path, &attributes) == 0 &&
           S_ISREG(attributes.st_mode);
}

bool is_dir(const char *path)
{
    struct stat attributes;

    return path != NULL && stat(path, &attributes) == 0 &&
           S_ISDIR(attributes.st_mode);
}

FILE *getFileHandle(const char *filename)
{
    FILE *handle = NULL;

    if (open_regular_file(filename, &handle) != MRSH_OK) {
        return NULL;
    }
    return handle;
}

static bool same_file_identity(const struct stat *left,
                               const struct stat *right)
{
    return left != NULL && right != NULL &&
           left->st_dev == right->st_dev && left->st_ino == right->st_ino;
}

static int descriptor_flags(int descriptor, int command)
{
    int result;

    do {
        result = fcntl(descriptor, command);
    } while (result < 0 && errno == EINTR);
    return result;
}

static int set_descriptor_flags(int descriptor, int command, int flags)
{
    int result;

    do {
        result = fcntl(descriptor, command, flags);
    } while (result < 0 && errno == EINTR);
    return result;
}

static int open_regular_file_impl(const char *filename,
                                  const struct stat *expected,
                                  bool follow_final_symlink,
                                  FILE **handle_out)
{
    struct stat attributes;
    FILE *handle;
    int descriptor;
    int open_flags = O_RDONLY | O_NONBLOCK;
    int status_flags;
    int fd_flags;
    int stat_result;

    if (handle_out == NULL) {
        return MRSH_ERR_INVALID;
    }
    *handle_out = NULL;
    if (filename == NULL || filename[0] == '\0') {
        return MRSH_ERR_INVALID;
    }
#ifdef O_CLOEXEC
    open_flags |= O_CLOEXEC;
#endif
#ifdef O_NOFOLLOW
    if (expected != NULL && !follow_final_symlink) {
        open_flags |= O_NOFOLLOW;
    }
#endif
    do {
        descriptor = open(filename, open_flags);
    } while (descriptor < 0 && errno == EINTR);
    if (descriptor < 0) {
        return MRSH_ERR_IO;
    }

    do {
        stat_result = fstat(descriptor, &attributes);
    } while (stat_result != 0 && errno == EINTR);
    if (stat_result != 0) {
        (void)close(descriptor);
        return MRSH_ERR_IO;
    }
    if (!S_ISREG(attributes.st_mode) ||
        (expected != NULL &&
         (!S_ISREG(expected->st_mode) ||
          !same_file_identity(&attributes, expected)))) {
        (void)close(descriptor);
        return MRSH_ERR_INVALID;
    }

    status_flags = descriptor_flags(descriptor, F_GETFL);
    if (status_flags < 0 ||
        set_descriptor_flags(descriptor, F_SETFL,
                             status_flags & ~O_NONBLOCK) < 0) {
        (void)close(descriptor);
        return MRSH_ERR_IO;
    }
    fd_flags = descriptor_flags(descriptor, F_GETFD);
    if (fd_flags < 0 ||
        set_descriptor_flags(descriptor, F_SETFD, fd_flags | FD_CLOEXEC) < 0) {
        (void)close(descriptor);
        return MRSH_ERR_IO;
    }

    handle = fdopen(descriptor, "rb");
    if (handle == NULL) {
        (void)close(descriptor);
        return MRSH_ERR_IO;
    }
    *handle_out = handle;
    return MRSH_OK;
}

int open_regular_file(const char *filename, FILE **handle_out)
{
    return open_regular_file_impl(filename, NULL, true, handle_out);
}

int open_regular_file_checked(const char *filename,
                              const struct stat *expected,
                              FILE **handle_out)
{
    if (expected == NULL) {
        if (handle_out != NULL) {
            *handle_out = NULL;
        }
        return MRSH_ERR_INVALID;
    }
    return open_regular_file_impl(filename, expected, false, handle_out);
}

int open_regular_file_follow_checked(const char *filename,
                                     const struct stat *expected,
                                     FILE **handle_out)
{
    if (expected == NULL) {
        if (handle_out != NULL) {
            *handle_out = NULL;
        }
        return MRSH_ERR_INVALID;
    }
    return open_regular_file_impl(filename, expected, true, handle_out);
}

int open_directory_checked(const char *filename,
                           const struct stat *expected,
                           DIR **directory_out)
{
    struct stat attributes;
    DIR *directory;
    int descriptor;
    int open_flags = O_RDONLY | O_NONBLOCK;
    int fd_flags;
    int stat_result;

    if (directory_out == NULL) {
        return MRSH_ERR_INVALID;
    }
    *directory_out = NULL;
    if (filename == NULL || filename[0] == '\0' || expected == NULL ||
        !S_ISDIR(expected->st_mode)) {
        return MRSH_ERR_INVALID;
    }
#ifdef O_CLOEXEC
    open_flags |= O_CLOEXEC;
#endif
#ifdef O_DIRECTORY
    open_flags |= O_DIRECTORY;
#endif
#ifdef O_NOFOLLOW
    open_flags |= O_NOFOLLOW;
#endif
    do {
        descriptor = open(filename, open_flags);
    } while (descriptor < 0 && errno == EINTR);
    if (descriptor < 0) {
        return MRSH_ERR_IO;
    }

    do {
        stat_result = fstat(descriptor, &attributes);
    } while (stat_result != 0 && errno == EINTR);
    if (stat_result != 0 || !S_ISDIR(attributes.st_mode) ||
        !same_file_identity(&attributes, expected)) {
        (void)close(descriptor);
        return stat_result != 0 ? MRSH_ERR_IO : MRSH_ERR_INVALID;
    }
    fd_flags = descriptor_flags(descriptor, F_GETFD);
    if (fd_flags < 0 ||
        set_descriptor_flags(descriptor, F_SETFD, fd_flags | FD_CLOEXEC) < 0) {
        (void)close(descriptor);
        return MRSH_ERR_IO;
    }
    directory = fdopendir(descriptor);
    if (directory == NULL) {
        (void)close(descriptor);
        return MRSH_ERR_IO;
    }
    *directory_out = directory;
    return MRSH_OK;
}
