
##########################
# User-accessible targets.

LLDB_FRAMEWORK := external/llvm/build/Library/Frameworks/LLDB.framework/Versions/A/LLDB
LIBCAPSTONE := external/capstone/libcapstone.a


all: build/crash-unscrambler

clean:
	rm -rf build /cores/core-to-unscramble

clean-external:
	rm -rf external/llvm/build
	make -C external/capstone clean

distclean: clean
	rm -rf download external

build/crash-unscrambler: src/lldbtest.cpp $(LLDB_FRAMEWORK) $(LIBCAPSTONE) /cores/core-to-unscramble | build
	DIR=`pwd` ; cd build ; clang++ -g -o crash-unscrambler ../src/lldbtest.cpp -std=c++17 -F ../external/llvm/build/Library/Frameworks -framework LLDB -rpath "$$DIR/external/llvm/build/Library/Frameworks" -I ../external/capstone/include -L ../external/capstone -lcapstone -Wall -Wno-stdlibcxx-not-found

# core file for crash-unscrambler to read
/cores/core-to-unscramble: build/make-core
	ulimit -c unlimited ; CORE=`build/make-core` ; echo "waiting for core $$CORE" ; while [ ! -f $$CORE ] ; do sleep 1 ; done ; mv -f $$CORE /cores/core-to-unscramble

build/make-core: src/make-core.cpp | build
	cd build; clang++ ../src/make-core.cpp -o make-core -g -O0 -Wno-stdlibcxx-not-found

# We don't try to rebuild external stuff if it is edited.
# Use these targets to manually rebuild.
#
# rebuild-llvm: defined below
# rebuild-lldb: defined below
# rebuild-capstone: defined below

# Path to cmake executable.
# Edit this if you have CMake.app installed in an unusual place.
CMAKE := $(shell which cmake || which /Applications/CMake.app/Contents/bin/cmake || which ~/Applications/CMake.app/Contents/bin/cmake)


####################################
## No user-serviceable parts inside.

.PHONY: swig-installed cmake-installed all rebuild-llvm rebuild-lldb rebuild-capstone

external:
	mkdir -p external

build:
	mkdir -p build


## llvm and lldb

SWIG := $(shell which swig)

cmake-installed:
ifeq (, $(CMAKE))
	$(error "No cmake in PATH or CMake.app in /Applications or ~/Applications. Please install CMake. (If you use Homebrew run `brew install cmake`).")
endif

swig-installed:
ifeq (, $(shell which swig))
	$(error "No swig in PATH. Please install swig. (If you use Homebrew run `brew install swig`).")
endif

rebuild-llvm rebuild-lldb $(LLDB_FRAMEWORK): | swig-installed cmake-installed external/llvm
	mkdir -p external/llvm/build
	$(CMAKE) -B external/llvm/build -S external/llvm/llvm -DLLVM_ENABLE_PROJECTS='clang;lldb' -DLLVM_PARALLEL_COMPILE_JOBS=8 -DLLDB_CODESIGN_IDENTITY='' -DSKIP_DEBUGSERVER=ON -DLLDB_BUILD_FRAMEWORK=ON
	make -C external/llvm/build -j8

external/llvm: | external
	if [ ! -f download/llvmorg.tar.gz ]; then mkdir -p download ; curl --location -o download/llvmorg.tar.gz 'https://github.com/llvm/llvm-project/archive/llvmorg-7.0.1.tar.gz' ; fi
	mkdir -p external/llvm
	tar -x -C external/llvm --strip-components 1 -zf download/llvmorg.tar.gz


## capstone

rebuild-capstone $(LIBCAPSTONE): | external/capstone
	cd external/capstone; env CAPSTONE_ARCHS="aarch64 x86" CAPSTONE_STATIC=yes CAPSTONE_SHARED=no ./make.sh clang

external/capstone: | external
	if [ ! -f download/capstone.tar.gz ]; then mkdir -p download ; curl --location -o download/capstone.tar.gz 'https://github.com/aquynh/capstone/archive/4.0.1.tar.gz' ; fi
	mkdir -p external/capstone
	tar -x -C external/capstone --strip-components 1 -zf download/capstone.tar.gz
