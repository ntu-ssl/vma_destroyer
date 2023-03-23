CC=gcc

TARGET = infinite_loop

$(TARGET): $(TARGET).c
	$(CC) -o $@ $^

.PHONY: all clean
all: $(TARGET)

clean:
	rm $(TARGET)