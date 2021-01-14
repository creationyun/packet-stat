LDLIBS=-lpcap

all: packet-stat

packet-stat: net-address.o protocol-hdr.o main.o
	$(LINK.cc) $^ $(LDLIBS) -o $@

clean:
	rm -f packet-stat *.o
