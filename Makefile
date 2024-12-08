CC = gcc
CFLAGS = -Wall -g `pkg-config fuse3 --cflags`
LDFLAGS = `pkg-config fuse3 --libs`

TARGET = bmpfs
SRC = bmpfs.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC) $(LDFLAGS)

clean:
	rm -f $(TARGET) *.o
