CC      = gcc
LD      = gcc
CFLAGS  = -Wall -g
LDFLAGS = -g -ldisasm
SRC     = tdb.c
OBJ     = tdb.o

.c.o:
	$(CC) $(CFLAGS) -c $<

tdb: $(OBJ)
	$(LD) $(LDFLAGS) -o $@ $(OBJ)

debuggee: debuggee.o
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f tdb
	rm -f *.obj
	rm -f *.o
	rm -f *.BAK
	rm -f *.asm
