LDLIBS=-lpcap

all: deauth-attack

deauth-attack: deauth-attack.o net-address.o
	$(LINK.cc) $^ $(LDLIBS) -o $@

clean:
	rm -f deauth-attack *.o

