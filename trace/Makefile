cur_dir := $(shell pwd)

srcs_trace := $(wildcard $(cur_dir)/*.c)
objs_trace := $(srcs_trace:.c=.o)

INCPATH := -I$(src_dir)/include
LDFLAGS := -lcap

all: second

%.o: %.c
	$(CC) $(CFLAGS) $(INCPATH) -c $<

second: $(objs_trace) $(wildcard $(src_dir)/lib/*.o)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)
