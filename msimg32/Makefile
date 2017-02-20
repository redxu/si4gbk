CC 		= gcc
CFLAGS 	= -O2 -Wall -static-libgcc
SRC 	= msimg32.c
OBJS 	= msimg32.o
DEF 	= msimg32.def
TARGET	= msimg32.dll


####### Implicit rules
.SUFFIXES: .o .c
	
.c.o:
	$(CC) -c $(CFLAGS) -o "$@" "$<"

all : $(TARGET)

$(TARGET) : $(OBJS)
	$(CC) -shared -Wl,--dll $(OBJS) $(CFLAGS) -o $(TARGET)


clean:
	rm -f $(TARGET) $(OBJS)