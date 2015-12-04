# top level makefile

export src_dir := $(shell pwd)
export CC := gcc
export CFLAGS := -ggdb -pedantic -O2 -D_FORTIFY_SOURCE=2 -W -Wall -Werror \
-Wextra -Wformat=2 -Wunused -Wmissing-prototypes -Wstrict-prototypes \
-Wconversion -Wshadow -Wcast-qual -Wwrite-strings -fstack-protector-strong

libs := lib
srcs := ginp trace
objs = $(wildcard $(src_dir)/*/*.o)

SUBDIRS := $(srcs) $(libs)
.PHONY: clean subdirs $(SUBDIRS)

subdirs: $(SUBDIRS)
$(srcs): $(libs)
$(SUBDIRS):
	$(MAKE) -C $@

clean:
	rm -rf $(objs) $(src_dir)/ginp/first $(src_dir)/trace/second
