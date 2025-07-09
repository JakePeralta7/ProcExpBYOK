CC=cl
RC=rc
CFLAGS=/W3 /O2 /D_CRT_SECURE_NO_WARNINGS
LIBS=kernel32.lib user32.lib advapi32.lib
TARGET=ProcExpBYOK.exe

SRCDIR=src
SOURCES=$(SRCDIR)\main.c
RESOURCES=$(SRCDIR)\resources.res

all: $(TARGET)

$(SRCDIR)\resources.res: $(SRCDIR)\resources.rc $(SRCDIR)\resource.h
	$(RC) /fo $@ $<

$(TARGET): $(SOURCES) $(RESOURCES)
	$(CC) $(CFLAGS) $(SOURCES) $(RESOURCES) /Fe$@ /link $(LIBS)

clean:
	del /Q *.exe *.obj *.res 2>nul

.PHONY: all clean
