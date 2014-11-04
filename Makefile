CC = gcc
CFLAGS = -Wall
TARGET = libdistorm3.so
COBJS = ExternalLib/distorm3/src/mnemonics.o ExternalLib/distorm3/src/wstring.o ExternalLib/distorm3/src/textdefs.o ExternalLib/distorm3/src/prefix.o ExternalLib/distorm3/src/operands.o ExternalLib/distorm3/src/insts.o ExternalLib/distorm3/src/instructions.o ExternalLib/distorm3/src/distorm.o ExternalLib/distorm3/src/decoder.o 
CFLAGS_D = -fPIC -O2 -Wall -DSUPPORT_64BIT_OFFSET -DDISTORM_STATIC

default: PErmutator

PErmutator: PEFunctions.o Disassembler.o TestMain.o Permutator.o distorm3.a
	$(CC) $(CFLAGS) -o PErmutator TestMain.o Permutator.o PEFunctions.o Disassembler.o -lstdc++ distorm3.a
	
TestMain.o: Source/TestMain.cpp Headers/PEFunctions.h Headers/Disassembler.h
	$(CC) $(CFLAGS) -c Source/TestMain.cpp -lstdc++
	
Permutator.o: Source/Permutator.cpp Headers/Permutator.h
	$(CC) $(CFLAGS) -c Source/Permutator.cpp -lstdc++
	
PEFunctions.o: Source/PEFunctions.cpp Headers/PEFunctions.h
	$(CC) $(CFLAGS) -c Source/PEFunctions.cpp -lstdc++
	
Disassembler.o: Source/Disassembler.cpp Headers/Disassembler.h Headers/distorm.h
	$(CC) $(CFLAGS) -c Source/Disassembler.cpp -lstdc++
	
distorm3.a: ${COBJS}
	${CC} ${CFLAGS} ${VERSION} ${COBJS} -shared -o ${TARGET}
	ar rs distorm3.a ${COBJS}
	
	
clean:
	rm -rf PErmutator *.o
