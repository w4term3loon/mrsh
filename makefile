CC ?= cc
CPPFLAGS ?=
CFLAGS ?= -std=c99 -O2 -Wall -Wextra -Wpedantic -Wmissing-prototypes
LDFLAGS ?=
LDLIBS ?=

MRSH_CPPFLAGS := -Iheader -D_DEFAULT_SOURCE
MRSH_LDLIBS := -lm
ifeq ($(shell uname -s),Linux)
MRSH_SHARED_LDFLAGS := -Wl,-Bsymbolic-functions
endif

NAME := mrsh
SOURCES := src/util.c src/hashing.c src/bloomfilter.c src/fingerprint.c src/fingerprintList.c src/helper.c src/traversal.c
HEADERS := $(wildcard header/*.h)
CLI_SOURCE := src/main.c
LIBRARY := bindings/mrshw/libmrsh.so
GLUE_SOURCE := bindings/glue/mrsh_glue.c
GLUE_HEADER := bindings/glue/mrsh_glue.h

.PHONY: all debug lib net sanitize clean

all: $(NAME)

$(NAME): $(SOURCES) $(HEADERS) $(CLI_SOURCE)
	$(CC) $(CPPFLAGS) $(MRSH_CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ $(CLI_SOURCE) $(SOURCES) $(LDLIBS) $(MRSH_LDLIBS)

debug:
	$(MAKE) -B CFLAGS="-std=c99 -O0 -g3 -Wall -Wextra -Wpedantic -Wmissing-prototypes" $(NAME)

net:
	$(MAKE) -B CPPFLAGS="$(CPPFLAGS) -Dnetwork" $(NAME)

lib: $(LIBRARY)

$(LIBRARY): $(SOURCES) $(HEADERS) $(GLUE_SOURCE) $(GLUE_HEADER)
	$(CC) $(CPPFLAGS) $(MRSH_CPPFLAGS) $(CFLAGS) -fPIC -fvisibility=hidden -shared $(LDFLAGS) $(MRSH_SHARED_LDFLAGS) -o $@ $(SOURCES) $(GLUE_SOURCE) $(LDLIBS) $(MRSH_LDLIBS)

sanitize:
	$(MAKE) clean
	$(MAKE) CFLAGS="-std=c99 -O1 -g3 -Wall -Wextra -Wpedantic -Wmissing-prototypes -Werror -fsanitize=address,undefined -fno-omit-frame-pointer" LDFLAGS="-fsanitize=address,undefined" $(NAME)

clean:
	rm -f -- $(NAME) $(LIBRARY)
