CC = gcc
CFLAGS = -Wall
TARGET = libdistorm3.so
COBJS = ../../src/mnemonics.o ../../src/wstring.o ../../src/textdefs.o ../../src/prefix.o ../../src/operands.o ../../src/insts.o ../../src/instructions.o ../../src/distorm.o ../../src/decoder.o
CFLAGS_D = -fPIC -O2 -Wall -DSUPPORT_64BIT_OFFSET -DDISTORM_STATIC

default: PErmutator

PErmutator: PEFunctions.o Disassembler.o TestMain.o Permutator.o distorm3.a
	$(CC) $(CFLAGS) -o PErmutator TestMain.o Permutator.o PEFunctions.o Disassembler.o -lstdc++ distorm3.a
	
TestMain.o: TestMain.cpp PEFunctions.h Disassembler.h
	$(CC) $(CFLAGS) -c TestMain.cpp -lstdc++
	
Permutator.o: Permutator.cpp Permutator.h
	$(CC) $(CFLAGS) -c Permutator.cpp -lstdc++
	
PEFunction.o: PEFunctions.cpp PEFunction.h
	$(CC) $(CFLAGS) -c PEFunctions.cpp -lstdc++
	
Disassembler.o: Disassembler.cpp Disassembler.h distorm.h
	$(CC) $(CFLAGS) -c Disassembler.cpp -lstdc++
	
distorm3.a: ${COBJS}
	${CC} ${CFLAGS} ${VERSION} ${COBJS} -shared -o ${TARGET}
	ar rs ../../distorm3.a ${COBJS}
	
	
clean:
	rm -rf PErmutator *.o
