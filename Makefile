CC=gcc
CFLAGS=-Werror -Wextra -std=c99 -Wall -g
VPATH=src
OBJS=main.o
BIN=my-kvm

$(BIN): $(OBJS)
	$(CC) $(CFLAGS) $^ -o $(BIN)

clean:
	rm $(BIN) $(OBJS)

