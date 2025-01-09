CC = gcc
CFLAGS = -Wall
LIBS = -lpcap

TARGET = bssid_print
SRCS = bssid_print.c

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRCS) $(LIBS)

clean:
	rm -f $(TARGET) 