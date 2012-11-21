CFLAGS = -fpic -fPIC -O0 -g3 -ggdb -shared -static-libgcc 
CFLAGS += -DMEMDBG_VERBOSE=1
CFLAGS += -DMEMDBG_DEBUG=1

all:
	g++ $(CFLAGS) -fno-exceptions -fno-rtti -L . -o libmemdbg.so main.cpp

clean:
	rm -f libmemdbg.so