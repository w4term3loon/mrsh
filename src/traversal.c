#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "../header/config.h"
#include "../header/traversal.h"

typedef struct {
    char *path;
    struct stat identity;
    unsigned int depth;
    size_t parent_index;
} PATH_RECORD;

typedef struct {
    PATH_RECORD *items;
    size_t size;
    size_t capacity;
} RECORD_LIST;

static bool same_identity(const struct stat *left, const struct stat *right)
{
    return left != NULL && right != NULL &&
           left->st_dev == right->st_dev && left->st_ino == right->st_ino;
}

static int duplicate_cloexec(int descriptor)
{
    int duplicate;

#ifdef F_DUPFD_CLOEXEC
    do {
        duplicate = fcntl(descriptor, F_DUPFD_CLOEXEC, 0);
    } while (duplicate < 0 && errno == EINTR);
#else
    do {
        duplicate = dup(descriptor);
    } while (duplicate < 0 && errno == EINTR);
    if (duplicate >= 0) {
        int flags;
        do {
            flags = fcntl(duplicate, F_GETFD);
        } while (flags < 0 && errno == EINTR);
        if (flags < 0 || fcntl(duplicate, F_SETFD, flags | FD_CLOEXEC) < 0) {
            (void)close(duplicate);
            duplicate = -1;
        }
    }
#endif
    return duplicate;
}

static int fstat_descriptor(int descriptor, struct stat *attributes)
{
    int result;

    do {
        result = fstat(descriptor, attributes);
    } while (result != 0 && errno == EINTR);
    return result == 0 ? MRSH_OK : MRSH_ERR_IO;
}

static int stat_component(int directory_descriptor, const char *name,
                          struct stat *attributes)
{
    int result;

    do {
        result = fstatat(directory_descriptor, name, attributes,
                         AT_SYMLINK_NOFOLLOW);
    } while (result != 0 && errno == EINTR);
    return result == 0 ? MRSH_OK : MRSH_ERR_IO;
}

static bool valid_component(const char *name)
{
    return name != NULL && name[0] != '\0' && strchr(name, '/') == NULL &&
           strcmp(name, ".") != 0 && strcmp(name, "..") != 0;
}

static int open_root_directory(const char *path,
                               const struct stat *expected,
                               int *descriptor_out)
{
    struct stat attributes;
    char *path_copy;
    char *cursor;
    size_t path_length;
    int descriptor;
    int flags = O_RDONLY | O_NONBLOCK;
    int status = MRSH_OK;

    if (path == NULL || path[0] == '\0' || expected == NULL ||
        descriptor_out == NULL || !S_ISDIR(expected->st_mode)) {
        return MRSH_ERR_INVALID;
    }
    *descriptor_out = -1;
    path_length = strnlen(path, FINGERPRINT_NAME_MAX);
    if (path_length >= FINGERPRINT_NAME_MAX) {
        return MRSH_ERR_RANGE;
    }
    path_copy = malloc(path_length + 1U);
    if (path_copy == NULL) {
        return MRSH_ERR_NOMEM;
    }
    memcpy(path_copy, path, path_length + 1U);
#ifdef O_CLOEXEC
    flags |= O_CLOEXEC;
#endif
#ifdef O_DIRECTORY
    flags |= O_DIRECTORY;
#endif
#ifdef O_NOFOLLOW
    flags |= O_NOFOLLOW;
#endif
    do {
        descriptor = open(path[0] == '/' ? "/" : ".", flags);
    } while (descriptor < 0 && errno == EINTR);
    if (descriptor < 0) {
        free(path_copy);
        return MRSH_ERR_IO;
    }

    /* Walk the caller-supplied root one component at a time. O_NOFOLLOW on a
     * whole pathname protects only its final component; descriptor-relative
     * opens are required to reject intermediate symlinks as well. */
    cursor = path_copy;
    while (*cursor != '\0') {
        char *component;
        char separator;

        while (*cursor == '/') {
            ++cursor;
        }
        if (*cursor == '\0') {
            break;
        }
        component = cursor;
        while (*cursor != '\0' && *cursor != '/') {
            ++cursor;
        }
        separator = *cursor;
        *cursor = '\0';

        if (strcmp(component, ".") != 0) {
            struct stat component_identity;
            struct stat opened_identity;
            int opened;

            status = stat_component(descriptor, component,
                                    &component_identity);
            if (status != MRSH_OK ||
                !S_ISDIR(component_identity.st_mode)) {
                status = status == MRSH_OK ? MRSH_ERR_INVALID : status;
                break;
            }
            do {
                opened = openat(descriptor, component, flags);
            } while (opened < 0 && errno == EINTR);
            if (opened < 0) {
                status = MRSH_ERR_IO;
                break;
            }
            status = fstat_descriptor(opened, &opened_identity);
            if (status != MRSH_OK || !S_ISDIR(opened_identity.st_mode) ||
                !same_identity(&opened_identity, &component_identity)) {
                (void)close(opened);
                status = status == MRSH_OK ? MRSH_ERR_INVALID : status;
                break;
            }
            (void)close(descriptor);
            descriptor = opened;
        }

        if (separator == '\0') {
            break;
        }
        *cursor = separator;
        ++cursor;
    }

    free(path_copy);
    if (status == MRSH_OK) {
        status = fstat_descriptor(descriptor, &attributes);
    }
    if (status != MRSH_OK || !S_ISDIR(attributes.st_mode) ||
        !same_identity(&attributes, expected)) {
        (void)close(descriptor);
        return status == MRSH_OK ? MRSH_ERR_INVALID : status;
    }
    *descriptor_out = descriptor;
    return MRSH_OK;
}

static int open_component_checked(int parent_descriptor, const char *name,
                                  const struct stat *expected,
                                  bool directory, int *descriptor_out)
{
    struct stat attributes;
    int descriptor;
    int flags = O_RDONLY | O_NONBLOCK;

    if (parent_descriptor < 0 || !valid_component(name) || expected == NULL ||
        descriptor_out == NULL ||
        (directory ? !S_ISDIR(expected->st_mode)
                   : !S_ISREG(expected->st_mode))) {
        return MRSH_ERR_INVALID;
    }
    *descriptor_out = -1;
#ifdef O_CLOEXEC
    flags |= O_CLOEXEC;
#endif
#ifdef O_NOFOLLOW
    flags |= O_NOFOLLOW;
#endif
#ifdef O_DIRECTORY
    if (directory) {
        flags |= O_DIRECTORY;
    }
#endif
    do {
        descriptor = openat(parent_descriptor, name, flags);
    } while (descriptor < 0 && errno == EINTR);
    if (descriptor < 0) {
        return MRSH_ERR_IO;
    }
    if (fstat_descriptor(descriptor, &attributes) != MRSH_OK ||
        (directory ? !S_ISDIR(attributes.st_mode)
                   : !S_ISREG(attributes.st_mode)) ||
        !same_identity(&attributes, expected)) {
        (void)close(descriptor);
        return MRSH_ERR_INVALID;
    }
    *descriptor_out = descriptor;
    return MRSH_OK;
}

static const char *record_name(const PATH_RECORD *record)
{
    const char *separator;

    if (record == NULL || record->path == NULL) {
        return NULL;
    }
    separator = strrchr(record->path, '/');
    return separator == NULL ? record->path : separator + 1;
}

static int open_directory_record(int root_descriptor,
                                 const RECORD_LIST *directories,
                                 size_t record_index,
                                 int *descriptor_out)
{
    size_t chain[MRSH_DIRECTORY_MAX_DEPTH + 2U];
    size_t chain_size = 0U;
    size_t cursor = record_index;
    int current;
    int status;

    if (directories == NULL || descriptor_out == NULL ||
        record_index >= directories->size) {
        return MRSH_ERR_INVALID;
    }
    while (cursor != SIZE_MAX) {
        if (cursor >= directories->size ||
            chain_size >= (size_t)MRSH_DIRECTORY_MAX_DEPTH + 2U) {
            return MRSH_ERR_INVALID;
        }
        chain[chain_size++] = cursor;
        cursor = directories->items[cursor].parent_index;
    }
    if (chain_size == 0U || chain[chain_size - 1U] != 0U) {
        return MRSH_ERR_INVALID;
    }

    *descriptor_out = -1;
    current = duplicate_cloexec(root_descriptor);
    if (current < 0) {
        return MRSH_ERR_IO;
    }
    {
        struct stat attributes;
        status = fstat_descriptor(current, &attributes);
        if (status != MRSH_OK || !S_ISDIR(attributes.st_mode) ||
            !same_identity(&attributes, &directories->items[0].identity)) {
            (void)close(current);
            return status == MRSH_OK ? MRSH_ERR_INVALID : status;
        }
    }
    while (chain_size > 1U) {
        const PATH_RECORD *record;
        const char *component;
        int opened = -1;

        --chain_size;
        record = &directories->items[chain[chain_size - 1U]];
        component = record_name(record);
        status = open_component_checked(current, component,
                                        &record->identity, true, &opened);
        if (status != MRSH_OK) {
            (void)close(current);
            return status;
        }
        (void)close(current);
        current = opened;
    }
    *descriptor_out = current;
    return MRSH_OK;
}

static int open_file_record(int root_descriptor,
                            const RECORD_LIST *directories,
                            const PATH_RECORD *file,
                            int *descriptor_out)
{
    const char *name;
    int parent = -1;
    int status;

    if (file == NULL || file->parent_index >= directories->size ||
        descriptor_out == NULL) {
        return MRSH_ERR_INVALID;
    }
    *descriptor_out = -1;
    name = record_name(file);
    if (!valid_component(name)) {
        return MRSH_ERR_INVALID;
    }
    status = open_directory_record(root_descriptor, directories,
                                   file->parent_index, &parent);
    if (status != MRSH_OK) {
        return status;
    }
    status = open_component_checked(parent, name, &file->identity, false,
                                    descriptor_out);
    (void)close(parent);
    return status;
}

static void record_list_destroy(RECORD_LIST *records)
{
    size_t index;

    if (records == NULL) {
        return;
    }
    for (index = 0U; index < records->size; ++index) {
        free(records->items[index].path);
    }
    free(records->items);
    records->items = NULL;
    records->size = 0U;
    records->capacity = 0U;
}

static int record_list_append(RECORD_LIST *records, const char *path,
                              const struct stat *identity,
                              unsigned int depth, size_t parent_index)
{
    PATH_RECORD *grown;
    char *copy;
    size_t length;

    if (records == NULL || path == NULL || identity == NULL) {
        return MRSH_ERR_INVALID;
    }
    length = strlen(path);
    if (length >= FINGERPRINT_NAME_MAX ||
        records->size >= (size_t)MRSH_TRAVERSAL_MAX_ENTRIES) {
        return MRSH_ERR_RANGE;
    }
    if (records->size == records->capacity) {
        size_t new_capacity = records->capacity == 0U
                                  ? 16U
                                  : records->capacity * 2U;
        if (new_capacity < records->capacity ||
            new_capacity > (size_t)MRSH_TRAVERSAL_MAX_ENTRIES) {
            new_capacity = (size_t)MRSH_TRAVERSAL_MAX_ENTRIES;
        }
        if (new_capacity <= records->capacity ||
            new_capacity > SIZE_MAX / sizeof(*records->items)) {
            return MRSH_ERR_RANGE;
        }
        grown = realloc(records->items,
                        new_capacity * sizeof(*records->items));
        if (grown == NULL) {
            return MRSH_ERR_NOMEM;
        }
        records->items = grown;
        records->capacity = new_capacity;
    }
    copy = malloc(length + 1U);
    if (copy == NULL) {
        return MRSH_ERR_NOMEM;
    }
    memcpy(copy, path, length + 1U);
    records->items[records->size].path = copy;
    records->items[records->size].identity = *identity;
    records->items[records->size].depth = depth;
    records->items[records->size].parent_index = parent_index;
    ++records->size;
    return MRSH_OK;
}

static int join_relative_path(const char *parent, const char *name,
                              char **path_out)
{
    size_t parent_length;
    size_t name_length;
    size_t separator;
    size_t total;
    char *path;

    if (parent == NULL || !valid_component(name) || path_out == NULL) {
        return MRSH_ERR_INVALID;
    }
    *path_out = NULL;
    parent_length = strlen(parent);
    name_length = strlen(name);
    separator = parent_length == 0U ? 0U : 1U;
    if (parent_length > SIZE_MAX - separator ||
        name_length > SIZE_MAX - parent_length - separator - 1U) {
        return MRSH_ERR_RANGE;
    }
    total = parent_length + separator + name_length;
    if (total >= FINGERPRINT_NAME_MAX) {
        return MRSH_ERR_RANGE;
    }
    path = malloc(total + 1U);
    if (path == NULL) {
        return MRSH_ERR_NOMEM;
    }
    memcpy(path, parent, parent_length);
    if (separator != 0U) {
        path[parent_length] = '/';
    }
    memcpy(path + parent_length + separator, name, name_length + 1U);
    *path_out = path;
    return MRSH_OK;
}

static int compare_records(const void *left, const void *right)
{
    const PATH_RECORD *left_record = left;
    const PATH_RECORD *right_record = right;

    return strcmp(left_record->path, right_record->path);
}

int visit_regular_files(const char *root_path,
                        const struct stat *expected_root,
                        bool recursive,
                        MRSH_REGULAR_FILE_VISITOR visitor,
                        void *context)
{
    RECORD_LIST directories = {0};
    RECORD_LIST files = {0};
    size_t visited_path_bytes = 1U;
    size_t visited_entries = 0U;
    size_t directory_index;
    int root_descriptor = -1;
    int status;

    if (visitor == NULL) {
        return MRSH_ERR_INVALID;
    }
    status = open_root_directory(root_path, expected_root, &root_descriptor);
    if (status != MRSH_OK) {
        return status;
    }
    status = record_list_append(&directories, "", expected_root, 0U,
                                SIZE_MAX);

    for (directory_index = 0U;
         status == MRSH_OK && directory_index < directories.size;
         ++directory_index) {
        PATH_RECORD current = directories.items[directory_index];
        int directory_descriptor = -1;
        DIR *directory;

        status = open_directory_record(root_descriptor, &directories,
                                       directory_index,
                                       &directory_descriptor);
        if (status != MRSH_OK) {
            break;
        }
        directory = fdopendir(directory_descriptor);
        if (directory == NULL) {
            (void)close(directory_descriptor);
            status = MRSH_ERR_IO;
            break;
        }

        for (;;) {
            struct dirent *entry;
            struct stat attributes;
            char *relative_path = NULL;

            errno = 0;
            entry = readdir(directory);
            if (entry == NULL) {
                if (errno != 0) {
                    status = MRSH_ERR_IO;
                }
                break;
            }
            if (strcmp(entry->d_name, ".") == 0 ||
                strcmp(entry->d_name, "..") == 0) {
                continue;
            }
            if (visited_entries >= (size_t)MRSH_TRAVERSAL_MAX_ENTRIES) {
                status = MRSH_ERR_RANGE;
                break;
            }
            ++visited_entries;
            status = stat_component(dirfd(directory), entry->d_name,
                                    &attributes);
            if (status != MRSH_OK) {
                break;
            }
            status = join_relative_path(current.path, entry->d_name,
                                        &relative_path);
            if (status != MRSH_OK) {
                break;
            }
            {
                size_t path_bytes = strlen(relative_path) + 1U;
                if (path_bytes > (size_t)MRSH_TRAVERSAL_MAX_PATH_BYTES -
                                     visited_path_bytes) {
                    free(relative_path);
                    status = MRSH_ERR_RANGE;
                    break;
                }
                visited_path_bytes += path_bytes;
            }
            if (S_ISREG(attributes.st_mode)) {
                status = record_list_append(&files, relative_path,
                                            &attributes, current.depth,
                                            directory_index);
            } else if (current.depth >= MRSH_DIRECTORY_MAX_DEPTH) {
                status = recursive && S_ISDIR(attributes.st_mode)
                             ? MRSH_ERR_RANGE
                             : MRSH_OK;
            } else if (recursive && S_ISDIR(attributes.st_mode)) {
                status = record_list_append(&directories, relative_path,
                                            &attributes,
                                            current.depth + 1U,
                                            directory_index);
            }
            free(relative_path);
            if (status != MRSH_OK) {
                break;
            }
        }
        if (closedir(directory) != 0 && status == MRSH_OK) {
            status = MRSH_ERR_IO;
        }
    }

    if (status == MRSH_OK && files.size > 1U) {
        qsort(files.items, files.size, sizeof(*files.items), compare_records);
    }
    if (status == MRSH_OK) {
        size_t file_index;
        for (file_index = 0U; file_index < files.size; ++file_index) {
            int descriptor = -1;
            int close_result;

            status = open_file_record(root_descriptor, &directories,
                                      &files.items[file_index], &descriptor);
            if (status != MRSH_OK) {
                break;
            }
            status = visitor(descriptor, files.items[file_index].path,
                             context);
            close_result = close(descriptor);
            if (status == MRSH_OK && close_result != 0) {
                status = MRSH_ERR_IO;
            }
            if (status != MRSH_OK) {
                break;
            }
        }
    }

    if (root_descriptor >= 0 && close(root_descriptor) != 0 &&
        status == MRSH_OK) {
        status = MRSH_ERR_IO;
    }
    record_list_destroy(&files);
    record_list_destroy(&directories);
    return status;
}
