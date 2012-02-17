all:
	gcc fcp.c -lssh -o fcp

clean:
	rm -f *o *out fcp *log
