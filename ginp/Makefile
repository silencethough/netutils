srcs_ginp := $(wildcard $(CURDIR)/*.c)
objs_ginp := $(srcs_ginp:.c=.o)

INCPATH := -I$(src_dir)/include
LDFLAGS := -lcap

all: first

%.o: %.c
	$(CC) $(CFLAGS) $(INCPATH) -c $^

first: $(objs_ginp) $(wildcard $(src_dir)/lib/*.o)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)
