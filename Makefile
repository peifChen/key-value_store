
cc = gcc
TARGET = ./out/kvstore 
SRCS = ./src/uring_server.c ./src/reactor_server.c ./src/nty_server.c ./src/array.c ./src/hash.c ./src/rbtree.c ./src/kvstore.c ./src/synchros.c ./src/persistence_binary.c ./src/incremental_persistence.c ./src/memory.c
INC = -I ./NtyCo/core/ -I ./include
LIBS = -L ./NtyCo/ -lntyco  -luring -lpthread -ljemalloc

all:

	$(cc) -o $(TARGET) $(SRCS) $(INC) $(LIBS)

clean:
	rm -rf kvstore