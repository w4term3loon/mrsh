NAME=mrsh
SOURCE=src/util.c src/hashing.c src/bloomfilter.c src/fingerprint.c src/fingerprintList.c src/helper.c
HEADER=header/util.h header/hashing.h header/bloomfilter.h header/fingerprint.h header/fingerprintList.h header/helper.h

CMD_TARGET=src/main.c

LIB_NAME=bindings/mrsh/_native.so
LIB_WRAPPER=bindings/mrsh/mrsh_wrapper.c

all: debug

mrsh: ${SOURCE} ${HEADER} ${CMD_TARGET}
	gcc -w -std=c99 -O3 -D_BSD_SOURCE -lcrypto -o ${NAME} ${CMD_TARGET} ${SOURCE} -lm

debug: ${SOURCE} ${HEADER} ${CMD_TARGET}
	gcc -w -ggdb -std=c99 -O0 -D_BSD_SOURCE -lcrypto -o ${NAME} ${CMD_TARGET} ${SOURCE} -lm

net: ${SOURCE} ${HEADER} ${CMD_TARGET}
	gcc -w -std=c99 -O3 -D_BSD_SOURCE -lcrypto -o ${NAME} ${CMD_TARGET} ${SOURCE} -Dnetwork -lm

lib: ${SOURCE} ${HEADER}
	gcc -w -Iheader -std=c99 -O3 -fPIC -shared -D_BSD_SOURCE -fvisibility=default -lcrypto -o ${LIB_NAME} ${SOURCE} ${LIB_WRAPPER} -lm

clean:
	rm -f ${NAME} *.o ${LIB_NAME}

# for DT_DIR feature to work, need to have the _BSD_SOURCE  feature test macro defined. These are not standard, and GCC does not define the macro when compiling for C99.


