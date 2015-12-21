CC = gcc

FLAGS = -g -O2 -D_REENTRANT -Wall

CFLAGS = ${FLAGS} -I/home/courses/cse533/Stevens/unpv13e/lib

LIBUNP_NAME = /home/courses/cse533/Stevens/unpv13e/libunp.a

LIBS = ${LIBUNP_NAME} -lpthread

CLEANFILES = core core.* server server.o client client.o odr odr.o

		
all: server client odr
	
server: server.o 
	${CC} ${FLAGS} -o server server.o ${LIBS}
server.o: server.c
	${CC} ${CFLAGS} -c server.c


client: client.o 
	${CC} ${FLAGS} -o client client.o ${LIBS}
client.o: client.c
	${CC} ${CFLAGS} -c client.c
	
odr: odr.o
	${CC} ${FLAGS} -o odr odr.o ${LIBS}
odr.o: odr.c
	${CC} ${CFLAGS} -c odr.c

clean:
	rm -f $(CLEANFILES)
