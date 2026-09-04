#ifndef MRSH_TRAVERSAL_H
#define MRSH_TRAVERSAL_H

#include <stdbool.h>
#include <sys/stat.h>

/* The descriptor is borrowed for the duration of the callback. */
typedef int (*MRSH_REGULAR_FILE_VISITOR)(int descriptor,
                                         const char *relative_path,
                                         void *context);

int visit_regular_files(const char *root_path,
                        const struct stat *expected_root,
                        bool recursive,
                        MRSH_REGULAR_FILE_VISITOR visitor,
                        void *context);

#endif /* MRSH_TRAVERSAL_H */
