CC 		= gcc
CFLAGS 	= -O2 -Wall -static-libgcc
SRC 	= si4gbk.c hook/hookapi.c hook/ldasm.c hack.c md5.c sifilemgr.c sihandlemgr.c \
          utf8.c utils.c winapihook.c
OBJS 	= si4gbk.o hook/hookapi.o hook/ldasm.o hack.o md5.o sifilemgr.o sihandlemgr.o \
          utf8.o utils.o winapihook.o
TARGET	= si4gbk.dll


####### Implicit rules
.SUFFIXES: .o .c
	
.c.o:
	$(CC) -c $(CFLAGS) -o "$@" "$<"

all : $(TARGET)

$(TARGET) : $(OBJS)
	$(CC) -shared -Wl,--dll $(OBJS) $(CFLAGS) -o $(TARGET)


clean:
	rm -f $(TARGET) $(OBJS)