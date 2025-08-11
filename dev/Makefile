
OUTPUT=bin/rsa

# define the ARM cross-compiler
AS= as
CC= gcc

# suppress warnings using -W
ASFLAGS=-g -W
CFLAGS=-g -Wall -Wextra

all: $(OUTPUT)

$(OUTPUT): bin/rsa_main.o bin/rsa_io.o bin/math_util.o bin/rsa_core.o 
	$(CC) $(CFLAGS) -o $@ $^

bin/rsa_main.o: rsa_main.s
	$(AS) $(ASFLAGS) -o $@ $<
bin/math_util.o: math_util.s
	$(AS) $(ASFLAGS) -o $@ $<
bin/rsa_io.o: rsa_io.s
	$(AS) $(ASFLAGS) -o $@ $<
bin/rsa_core.o: rsa_core.s
	$(AS) $(ASFLAGS) -o $@ $<

clean:
	rm -f bin/*.o $(OUTPUT)

