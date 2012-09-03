all:
	gcc fcp.c -lssh -o fcp

clean:
	rm -f *o *out fcp *log

install:
	gcc fcp.c -lssh -o ~/bin/fcp
