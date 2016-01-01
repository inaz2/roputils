CC := gcc
CFLAGS := -fno-stack-protector

bof: bof.c

.PHONY: clean getoffset
clean:
	$(RM) bof

getoffset: bof
	python getoffset.py ./bof
