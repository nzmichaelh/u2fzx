# Outer makefile to make using CMake

DTS = $(wildcard *.overlay)
BOARDS = $(DTS:%.overlay=%)

all: $(BOARDS:%=%.build)

%.build:
	mkdir -p build/$*
	cd build/$* && cmake ../.. -GNinja -DBOARD=$*
	ninja -C build/$*

clean:
	rm -fr build
