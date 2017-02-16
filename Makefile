CFLAGS := -O2 -Wall -W -Wextra -Wunused  -Wmissing-prototypes -Wstrict-prototypes
CC := gcc
LDFLAGS := -lcap
INCLUDEPATH := -I.
DEPFLAG := -MMD

objs := $(patsubst %.c,%.o,$(wildcard *.c))
deps := $(patsubst %.c,%.d,$(wildcard *.c))

all: myping mytrace
-include $(deps)

%.o: %.c
	$(CC) $(INCLUDEPATH) $(DEPFLAG) $(CFLAGS) -c $< -o $@
myping: inp.o cap.o cksum.o
	$(CC) $^ -o $@ $(LDFLAGS)
mytrace: route.o cap.o cksum.o
	$(CC) $^ -o $@ $(LDFLAGS)

.PHONY: clean
clean:
	rm -f $(objs) $(deps) myping mytrace
