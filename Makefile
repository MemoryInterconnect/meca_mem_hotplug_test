CROSS_COMPILE ?= riscv64-linux-gnu-
CC = $(CROSS_COMPILE)gcc
CFLAGS = -Wall -Wextra -O2
LDFLAGS = -static

TARGET = meca_mem_hotplug_test
SRC = meca_mem_hotplug_test.c

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

clean:
	rm -f $(TARGET)
