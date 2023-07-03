CC = gcc -std=gnu99
CFLAGS += -fPIC
CFLAGS += -Wall
CFLAGS += -Wextra
# turn warnings into errors
CFLAGS += -Werror

# Optimize Build
DEBUG_FLAGS = -g0 -Os
# Build with full debug and no optimization
# DEBUG_FLAGS = -g3 -O0
DEFINES =

OPENLIBS = -I ./include -I/usr/local/include/curl -L/usr/local/lib
OPENLIBS = -lcrypto -lcurl

OSRC := $(wildcard src/*.c) \
        $(wildcard src/openssl_wrapper/*.c) \
        $(wildcard lib/src/*.c)
OOBJ = $(OSRC:%.c=%.o)

# The base openSSL build for a 64-bit OS
openssl: DEFINES += -D__OPEN_SSL__
openssl: ${OOBJ}
	${CC} ${CFLAGS} ${DEBUG_FLAGS} ${DEFINES} -o keyfactor-c-estclient $^ ${OPENLIBS}

# The base openSSL build to create a shared library
openlib: DEFINES += -D__OPEN_SSL__ -D__MAKE_LIBRARY__
openlib: ${OOBJ}
	${CC} -shared ${CFLAGS} ${DEBUG_FLAGS} ${DEFINES} -o keyfactor-c-estclient.so $^ ${OPENLIBS}

# The openSSL build for any 32-bit OS like RaspOS
openpi: DEFINES += -D__OPEN_SSL__ -Wno-format
openpi: ${OOBJ}
	${CC} ${CFLAGS} ${DEBUG_FLAGS} ${DEFINES} -o keyfactor-c-estclient $^ ${OPENLIBS}

# How to install the shared library
openinstall: libagent.so
	sudo cp libagent.so /usr/lib
	sudo chmod 755 /usr/lib/est-lite.so

# define the builds
%.o: %.c
	$(info building $@ from $<)
	- @${CC} ${CFLAGS} ${DEFINES} ${WARN_FLAGS} ${DEBUG_FLAGS} ${C_STD} -c -o $@ $<

# define the clean or delete commands
.PHONY: deleteallobs
deleteallobs:
	rm -rf ${OBJS} ${OOBJ} keyfactor-c-estclient

.PHONY: cleanall
cleanall: deleteallobs

.PHONY: clean
clean: deleteallobs

.PHONY: all
all: openssl
