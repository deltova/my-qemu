CC=g++
CFLAGS=-Werror -Wextra -std=c++17 -Wall -g
LDFLAGS=-lcapstone
VPATH=src
OBJS=main.o debug.o serial.o
BIN=my-kvm

$(BIN): $(OBJS)
	$(CC) $(LDFLAGS) $(CFLAGS)  $^ -o $(BIN)

clean:
	rm $(BIN) $(OBJS)

