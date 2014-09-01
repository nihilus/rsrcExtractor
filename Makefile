CCFLAGS=-D__IDP__ -D__LINUX__ -fPIC -Wno-format -O3
CCFLAGS64=-D__IDP__ -D__LINUX__ -D__EA64__ -fPIC -Wno-format -O3
LIBPATH=	#set to path of IDA directory
LDFLAGS= -shared --export-dynamic
INCLUDE= 	#set to path of IDA SDK include directory

all:rsrcExtractor.plx rsrcExtractor.plx64 postmortem
clean:
	rm -rf *.o
	rm -rf *.o64
	rm *.plx
	rm *.plx64

postmortem:
	chmod	644 *.plx
	chmod	644 *.plx64
	strip rsrcExtractor.plx
	strip rsrcExtractor.plx64

rsrcExtractor.plx:main.o rsrc.o
	gcc -m32 $(LDFLAGS) main.o rsrc.o -o rsrcExtractor.plx -L$(LIBPATH) -lida
	rm -rf *.o

rsrcExtractor.plx64:main.o64 rsrc.o64
	gcc -m32 $(LDFLAGS) main.o64 rsrc.o64 -o rsrcExtractor.plx64 -L$(LIBPATH) -lida64
	rm -rf *.o64

rsrc.o64:rsrc.cpp
	gcc -m32 -I$(INCLUDE) $(CCFLAGS64) -c rsrc.cpp -o $@
rsrc.o:rsrc.cpp
	gcc -m32 -I$(INCLUDE) $(CCFLAGS) -c rsrc.cpp -o $@
main.o64:main.cpp
	gcc -m32 -I$(INCLUDE) $(CCFLAGS64) -c main.cpp -o $@
main.o:main.cpp
	gcc -m32 -I$(INCLUDE) $(CCFLAGS) -c main.cpp -o $@
