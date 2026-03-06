CC = gcc
CFLAGS = -Wall -Wextra
TARGET = packet_sniffer
SRC = packet_sniffer.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC)

clean:
	rm -f $(TARGET)

run: $(TARGET)
	@echo "Note: Packet sniffer requires root privileges"
	@echo "Run: sudo ./$(TARGET)"

.PHONY: all clean run
