cur_dir := $(shell pwd)

srcs_lib := $(wildcard $(cur_dir)/*.c)
objs_lib := $(srcs_lib:.c=.o)

INCPATH := -I$(src_dir)/include

all: $(objs_lib)

$(objs_lib): $(srcs_lib)
	$(CC) $(CFLAGS) $(INCPATH) -c $^

.PHONY: clean
clean:
	rm -rf $(objs_lib)
