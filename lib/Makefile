INCPATH := -I$(src_dir)/include

all: *.o

%.o: %.c
	$(CC) $(CFLAGS) $(INCPATH) -c $^

.PHONY: clean
clean:
	rm -rf *.o
