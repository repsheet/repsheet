CC ?= cc
UNAME_S := $(shell uname -s)

CFLAGS ?= -O2 -g
CFLAGS += -std=c11 -D_DEFAULT_SOURCE -fPIC -fvisibility=hidden -Wall -Wextra -Wno-unused-parameter \
          -Iinclude -I../common
ifeq ($(SANITIZE),1)
  CFLAGS += -fsanitize=address,undefined -fno-omit-frame-pointer
  LDFLAGS += -fsanitize=address,undefined
endif
ifeq ($(UNAME_S),Darwin)
  SHOBJ_LDFLAGS ?= -bundle -undefined dynamic_lookup
else
  SHOBJ_LDFLAGS ?= -shared -Wl,-Bsymbolic
endif

OBJS = src/repsheet.o ../common/repsheet_actor.o

all: repsheet.so

repsheet.so: $(OBJS)
	$(CC) -o $@ $(OBJS) $(SHOBJ_LDFLAGS) $(LDFLAGS)

src/repsheet.o: src/repsheet.c include/redismodule.h ../common/repsheet_actor.h
../common/repsheet_actor.o: ../common/repsheet_actor.c ../common/repsheet_actor.h

clean:
	rm -f repsheet.so $(OBJS)

.PHONY: all clean
