PROTOC = protoc
CFLAGS = -g -I. -Wall -Werror $(OS_CFLAGS)
LDFLAGS = -g $(OS_LDFLAGS)

# OS_ vars might depend on your local distro...
OS_CFLAGS = -I /usr/include/crypto++
OS_LDFLAGS = -lgit2 -lcrypto++ `pkg-config --libs protobuf`

# You probably want to customize this...
INSTALL_PREFIX = $(HOME)/git-bin

default : filter selftest

selftest: filter
	cd test && mkdir -p out && \
	../filter -mode selftest -access_map test.access_map

clean:
	rm -f *.pb.h *.pb.cc *.o filter

filter : filter.o filter.pb.o
	g++ -o filter filter.o filter.pb.o $(LDFLAGS)

filter.o : filter.cc filter.pb.h
	g++ $(CFLAGS) -o filter.o -c filter.cc

filter.pb.o : filter.pb.h
	g++ $(CFLAGS) -o filter.pb.o -c filter.pb.cc

# Don't mention filter.pb.cc, since listing two targets
# means it might run $(PROTOC) twice under make -j  ...
filter.pb.h : filter.proto
	$(PROTOC) --cpp_out=. $<

install: filter
	mkdir -p $(INSTALL_PREFIX) && \
	cp -f filter $(INSTALL_PREFIX)
