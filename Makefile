CC = gcc
CFLAGS = -Wall -Wextra
LIBS = -lpcap

TARGET = bssid_print
SRCS = bssid_print.c
OBJS = $(SRCS:.c=.o)
HEADERS = radiotap.h

$(TARGET): $(OBJS)
	$(CC) $(OBJS) -o $(TARGET) $(LIBS)

%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(TARGET) $(OBJS)

.PHONY: clean 