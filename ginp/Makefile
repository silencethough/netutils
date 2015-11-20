cur_dir := $(shell pwd)

srcs_ginp := $(wildcard $(cur_dir)/*.c)
objs_ginp := $(srcs_ginp:.c=.o)

INCPATH := -I$(src_dir)/include
LDFLAGS := -lcap

all: first

%.o: %.c
	$(CC) $(CFLAGS) $(INCPATH) -c $^

first: *.o $(src_dir)/lib/*.o
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

.PHONY: clean
clean:
	rm -rf $(objs_ginp) first
