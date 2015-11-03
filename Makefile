export src_dir := $(shell pwd)
export CC := gcc
export CFLAGS := -std=gnu89 -ggdb -pedantic -O2 -D_FORTIFY_SOURCE=2 -W -Wall \
-Werror -Wextra -Wformat=2 -Wunused -Wmissing-prototypes -Wstrict-prototypes \
-Wconversion -Wshadow -Wcast-qual -Wwrite-strings -fstack-protector-strong

DIRS = lib ginp trace

all:
	@ for dir_list in ${DIRS}; do (cd $${dir_list}; $(MAKE)); done

.PHONY: clean
clean:
	@ for dir_list in ${DIRS}; do (cd $${dir_list}; $(MAKE) clean); done
