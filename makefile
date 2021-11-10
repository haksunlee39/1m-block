LDLIBS=-lnetfilter_queue
	
all: 1m-block

1m-block: main.o
	g++ -o 1m-block main.o $(LDLIBS)

main.o: 1m-block.h main.cpp

clean:
	rm -f 1m-block
	rm -f *.o
