#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "../header/helper.h"
#include "../header/hashing.h"
#include "../header/main.h"
#include "../header/traversal.h"

MODES *mode = NULL;

static int show_help(FILE *stream)
{
    return fprintf(stream,
        "mrsh\n\n"
        "Usage: mrsh [-cgpfrh] [-t VALUE] [-L LIST] [-l LIST] [PATH ...]\n"
        "  -c  compare exactly two files or directories\n"
        "  -g  compare all files in the supplied paths\n"
        "  -L  compare a digest list with itself or one other list\n"
        "  -l  compare a digest list with files or directories\n"
        "  -p  print digests for supplied files or directories\n"
        "  -f  normalize comparison scores by the larger fingerprint\n"
        "  -r  scan directories recursively\n"
        "  -t  print scores from 0 through 100 at or above VALUE\n"
        "  -h  show this help\n") < 0 ? MRSH_ERR_IO : MRSH_OK;
}

static int initialize_modes(void)
{
    mode = calloc(1U, sizeof(*mode));
    if (mode == NULL) {
        return MRSH_ERR_NOMEM;
    }
    mode->threshold = 1;
    return MRSH_OK;
}

static int parse_threshold(const char *text, int *threshold_out)
{
    char *end = NULL;
    long value;

    if (text == NULL || text[0] == '\0' || threshold_out == NULL) {
        return MRSH_ERR_INVALID;
    }
    errno = 0;
    value = strtol(text, &end, 10);
    if (errno == ERANGE || end == text || *end != '\0' ||
        value < 0L || value > 100L) {
        return MRSH_ERR_RANGE;
    }
    *threshold_out = (int)value;
    return MRSH_OK;
}

static char *join_path(const char *directory, const char *entry)
{
    size_t directory_length;
    size_t entry_length;
    size_t separator_length;
    size_t total_length;
    char *result;

    if (directory == NULL || entry == NULL) {
        return NULL;
    }
    directory_length = strlen(directory);
    entry_length = strlen(entry);
    separator_length =
        directory_length != 0U && directory[directory_length - 1U] == '/' ? 0U : 1U;
    if (entry_length > SIZE_MAX - separator_length - 1U ||
        directory_length >
            SIZE_MAX - entry_length - separator_length - 1U) {
        return NULL;
    }
    total_length = directory_length + separator_length + entry_length + 1U;
    result = malloc(total_length);
    if (result == NULL) {
        return NULL;
    }
    (void)snprintf(result, total_length, "%s%s%s", directory,
                   separator_length == 0U ? "" : "/", entry);
    return result;
}

static int add_regular_file(FINGERPRINT_LIST *fpl, const char *filename,
                            const struct stat *expected,
                            bool follow_final_symlink)
{
    FILE *file;
    FINGERPRINT *fingerprint;
    int status;

    if (expected != NULL && follow_final_symlink) {
        status = open_regular_file_follow_checked(filename, expected, &file);
    } else if (expected != NULL) {
        status = open_regular_file_checked(filename, expected, &file);
    } else {
        status = open_regular_file(filename, &file);
    }
    if (status != MRSH_OK) {
        return status;
    }
    fingerprint = init_fingerprint_for_file(file, filename);
    if (fingerprint == NULL) {
        return MRSH_ERR_IO;
    }
    status = add_new_fingerprint(fpl, fingerprint);
    if (status != MRSH_OK) {
        (void)fingerprint_destroy(fingerprint);
    }
    return status;
}

typedef struct {
    FINGERPRINT_LIST *list;
    const char *root_path;
} CLI_VISITOR_CONTEXT;

static int add_visited_file(int descriptor, const char *relative_path,
                            void *opaque_context)
{
    CLI_VISITOR_CONTEXT *context = opaque_context;
    FINGERPRINT *fingerprint;
    char *display_path;
    int status;

    if (context == NULL || context->list == NULL || relative_path == NULL) {
        return MRSH_ERR_INVALID;
    }
    display_path = join_path(context->root_path, relative_path);
    if (display_path == NULL) {
        return MRSH_ERR_NOMEM;
    }
    fingerprint = init_empty_fingerprint();
    if (fingerprint == NULL) {
        free(display_path);
        return MRSH_ERR_NOMEM;
    }
    status = fingerprint_set_name(fingerprint, display_path);
    if (status == MRSH_OK) {
        status = hashFileDescriptorToFingerprint(fingerprint, descriptor);
    }
    if (status == MRSH_OK) {
        status = add_new_fingerprint(context->list, fingerprint);
    }
    if (status != MRSH_OK) {
        (void)fingerprint_destroy(fingerprint);
    }
    free(display_path);
    return status;
}

int addPathToFingerprintList(FINGERPRINT_LIST *fpl, const char *filename)
{
    struct stat attributes;
    bool follow_symlink = false;

    if (fpl == NULL || filename == NULL || filename[0] == '\0') {
        return MRSH_ERR_INVALID;
    }
    if (lstat(filename, &attributes) != 0) {
        return MRSH_ERR_IO;
    }
    if (S_ISLNK(attributes.st_mode)) {
        if (stat(filename, &attributes) != 0) {
            return MRSH_ERR_IO;
        }
        if (!S_ISREG(attributes.st_mode)) {
            return MRSH_ERR_INVALID;
        }
        follow_symlink = true;
    }
    if (S_ISREG(attributes.st_mode)) {
        return add_regular_file(fpl, filename, &attributes, follow_symlink);
    }
    if (!S_ISDIR(attributes.st_mode)) {
        return MRSH_ERR_INVALID;
    }
    {
        CLI_VISITOR_CONTEXT context = {fpl, filename};
        return visit_regular_files(filename, &attributes,
                                   mode != NULL && mode->recursive,
                                   add_visited_file, &context);
    }
}

static int add_paths(FINGERPRINT_LIST *fpl, int argc, char **argv, int start)
{
    int index;

    for (index = start; index < argc; ++index) {
        int status = addPathToFingerprintList(fpl, argv[index]);
        if (status != MRSH_OK) {
            size_t path_length = strnlen(argv[index], FINGERPRINT_NAME_MAX);
            size_t path_index;

            (void)fputs("mrsh: cannot process '", stderr);
            for (path_index = 0U; path_index < path_length; ++path_index) {
                unsigned char byte = (unsigned char)argv[index][path_index];
                if (byte >= 0x20U && byte <= 0x7eU &&
                    byte != (unsigned char)'\\' &&
                    byte != (unsigned char)'\'') {
                    (void)fputc((int)byte, stderr);
                } else {
                    (void)fprintf(stderr, "\\x%02X", (unsigned int)byte);
                }
            }
            if (path_length == FINGERPRINT_NAME_MAX) {
                (void)fputs("...", stderr);
            }
            (void)fputs("'\n", stderr);
            return status;
        }
    }
    return MRSH_OK;
}

static int run_print(int argc, char **argv, int start)
{
    FINGERPRINT_LIST *list;
    int status;

    if (start >= argc) {
        return MRSH_ERR_INVALID;
    }
    list = init_empty_fingerprintList();
    if (list == NULL) {
        return MRSH_ERR_NOMEM;
    }
    status = add_paths(list, argc, argv, start);
    if (status == MRSH_OK) {
        status = print_fingerprintList(list);
    }
    (void)fingerprintList_destroy(list);
    return status;
}

static int run_generate_compare(int argc, char **argv, int start)
{
    FINGERPRINT_LIST *list;
    int status;

    if (start >= argc) {
        return MRSH_ERR_INVALID;
    }
    list = init_empty_fingerprintList();
    if (list == NULL) {
        return MRSH_ERR_NOMEM;
    }
    status = add_paths(list, argc, argv, start);
    if (status == MRSH_OK) {
        status = all_against_all_comparsion(list);
    }
    (void)fingerprintList_destroy(list);
    return status;
}

static int run_list_compare(const char *list_name, int argc, char **argv,
                            int start)
{
    FINGERPRINT_LIST *first;
    int status = MRSH_OK;

    if (argc - start > 1) {
        return MRSH_ERR_INVALID;
    }
    first = init_fingerprintList_for_ListFile(list_name);
    if (first == NULL) {
        return MRSH_ERR_FORMAT;
    }
    if (argc == start) {
        status = all_against_all_comparsion(first);
    } else {
        FINGERPRINT_LIST *second =
            init_fingerprintList_for_ListFile(argv[start]);
        if (second == NULL) {
            status = MRSH_ERR_FORMAT;
        } else {
            status = fingerprint_list_comparsion(first, second);
            (void)fingerprintList_destroy(second);
        }
    }
    (void)fingerprintList_destroy(first);
    return status;
}

static int run_path_list_compare(const char *list_name, int argc, char **argv,
                                 int start)
{
    FINGERPRINT_LIST *list;
    FINGERPRINT_LIST *paths;
    int status;

    if (start >= argc) {
        return MRSH_ERR_INVALID;
    }
    list = init_fingerprintList_for_ListFile(list_name);
    paths = init_empty_fingerprintList();
    if (list == NULL || paths == NULL) {
        (void)fingerprintList_destroy(list);
        (void)fingerprintList_destroy(paths);
        return MRSH_ERR_FORMAT;
    }
    status = add_paths(paths, argc, argv, start);
    if (status == MRSH_OK) {
        status = fingerprint_list_comparsion(list, paths);
    }
    (void)fingerprintList_destroy(list);
    (void)fingerprintList_destroy(paths);
    return status;
}

static int run_pair_compare(int argc, char **argv, int start)
{
    FINGERPRINT_LIST *first;
    FINGERPRINT_LIST *second;
    int status;

    if (argc - start != 2) {
        return MRSH_ERR_INVALID;
    }
    first = init_empty_fingerprintList();
    second = init_empty_fingerprintList();
    if (first == NULL || second == NULL) {
        (void)fingerprintList_destroy(first);
        (void)fingerprintList_destroy(second);
        return MRSH_ERR_NOMEM;
    }
    status = addPathToFingerprintList(first, argv[start]);
    if (status == MRSH_OK) {
        status = addPathToFingerprintList(second, argv[start + 1]);
    }
    if (status == MRSH_OK) {
        status = fingerprint_list_comparsion(first, second);
    }
    (void)fingerprintList_destroy(first);
    (void)fingerprintList_destroy(second);
    return status;
}

int main(int argc, char **argv)
{
    const char *list_name = NULL;
    bool saw_operation = false;
    bool saw_option = false;
    bool usage_error = false;
    unsigned int primary_operation_count = 0U;
    int option;
    int status;

    if (initialize_modes() != MRSH_OK) {
        (void)fprintf(stderr, "mrsh: out of memory\n");
        return EXIT_FAILURE;
    }

    while ((option = getopt(argc, argv, "cgL:l:pfrt:h")) != -1) {
        saw_option = true;
        switch (option) {
        case 'c': mode->compare = true; saw_operation = true; ++primary_operation_count; break;
        case 'g': mode->gen_compare = true; saw_operation = true; ++primary_operation_count; break;
        case 'L':
            mode->compareLists = true;
            list_name = optarg;
            saw_operation = true;
            ++primary_operation_count;
            break;
        case 'l':
            mode->path_list_compare = true;
            list_name = optarg;
            saw_operation = true;
            ++primary_operation_count;
            break;
        case 'p': mode->print = true; saw_operation = true; ++primary_operation_count; break;
        case 'f': mode->file_comparison = true; break;
        case 'r': mode->recursive = true; break;
        case 't':
            if (parse_threshold(optarg, &mode->threshold) != MRSH_OK) {
                (void)fprintf(stderr, "mrsh: threshold must be an integer from 0 to 100\n");
                free(mode);
                mode = NULL;
                return EXIT_FAILURE;
            }
            break;
        case 'h': mode->helpmessage = true; break;
        default: usage_error = true; break;
        }
    }

    if (usage_error) {
        (void)show_help(stderr);
        free(mode);
        mode = NULL;
        return EXIT_FAILURE;
    }
    if (mode->helpmessage) {
        status = show_help(stdout);
        if (status == MRSH_OK && fflush(stdout) != 0) {
            status = MRSH_ERR_IO;
        }
        free(mode);
        mode = NULL;
        return status == MRSH_OK ? EXIT_SUCCESS : EXIT_FAILURE;
    }
    if (!saw_operation && !saw_option) {
        mode->print = true;
        saw_operation = true;
        primary_operation_count = 1U;
    }
    if (!saw_operation) {
        (void)fprintf(stderr, "mrsh: no operation selected\n");
        (void)show_help(stderr);
        free(mode);
        mode = NULL;
        return EXIT_FAILURE;
    }
    if (primary_operation_count != 1U) {
        (void)fprintf(stderr,
                      "mrsh: choose exactly one of -p, -c, -g, -L, or -l\n");
        free(mode);
        mode = NULL;
        return EXIT_FAILURE;
    }

    status = MRSH_OK;
    if (mode->print) {
        status = run_print(argc, argv, optind);
    } else {
        if (mode->gen_compare) {
            status = run_generate_compare(argc, argv, optind);
        }
        if (status == MRSH_OK && mode->compareLists) {
            status = run_list_compare(list_name, argc, argv, optind);
        }
        if (status == MRSH_OK && mode->path_list_compare) {
            status = run_path_list_compare(list_name, argc, argv, optind);
        }
        if (status == MRSH_OK && mode->compare) {
            status = run_pair_compare(argc, argv, optind);
        }
    }

    if (status == MRSH_OK && fflush(stdout) != 0) {
        status = MRSH_ERR_IO;
    }
    if (status != MRSH_OK) {
        (void)fprintf(stderr, "mrsh: operation failed (error %d)\n", status);
    }
    free(mode);
    mode = NULL;
    return status == MRSH_OK ? EXIT_SUCCESS : EXIT_FAILURE;
}
