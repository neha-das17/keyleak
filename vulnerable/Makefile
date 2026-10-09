CC = gcc

CFLAGS = -Wall -Wextra -g

LIBS = -lcrypto

TARGET = server

SOURCE = server.c

all:
	$(CC) $(CFLAGS) $(SOURCE) -o $(TARGET) $(LIBS)

clean:
	rm -f $(TARGET)

run: $(TARGET)
	./$(TARGET)
