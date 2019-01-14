CC=gcc
CFLAGS=-Werror -Wextra -std=c99 -Wall -g
LDFLAGS=-lcapstone
VPATH=src
OBJS=main.o debug.o
BIN=my-kvm

$(BIN): $(OBJS)
	$(CC) $(LDFLAGS) $(CFLAGS)  $^ -o $(BIN)

clean:
	rm $(BIN) $(OBJS)

