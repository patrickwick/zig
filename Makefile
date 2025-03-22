# Temporary convenience Makefile to create named targets for a combination of Zig and other tools.
ZIG=zig
ZIG_LIB_DIR=./lib

DEBUGGER=gdb

all: test-integration

# Most important flags from `zig build --help`:
# -Dno-lib: skip copying libc and zig std library files to prefix
# -Dno-bin: skip emitting compiler binary
# -Ddev=x86_64-linux: x64 backend only for faster compilation
# -Ddebug-extensions=true: enable --verbose-air and other debug dumps

.PHONY: build
build:
	time ${ZIG} build \
		-Doptimize=Debug \
		-Ddebug-extensions=true \
		-Dlog=true \
		-Dno-lib \
		-Duse-llvm=false \
		-Ddev=x86_64-linux \
		--zig-lib-dir ${ZIG_LIB_DIR} \
		--summary all

# ./zig-out/bin/zig build-obj ./test.zig
.PHONY: test-unit
test-unit:
	time ${ZIG} build test-unit \
		-Ddebug-extensions=true \
		-Dno-lib \
		-Dno-bin \
		-Duse-llvm=false \
		-Ddev=x86_64-linux \
		--zig-lib-dir ${ZIG_LIB_DIR} \
		--summary all

.PHONY: test-debug
test-debug:
	time ${ZIG} build test-unit \
		-Ddebug-extensions=true \
		-Dno-lib \
		-Dno-bin \
		-Duse-llvm=false \
		-Ddev=x86_64-linux \
		--zig-lib-dir ${ZIG_LIB_DIR} \
		--summary all

.PHONY: test-watch
test-watch:
	time ${ZIG} build test-unit \
		-Dno-lib \
		-Dno-bin \
		-Duse-llvm=false \
		-Ddev=x86_64-linux \
		--zig-lib-dir ${ZIG_LIB_DIR} \
		--summary all \
		-fincremental \
		--watch

.PHONY: test
test:
	time ${ZIG} test ./src/export_air.zig \
		-fno-llvm \
		--zig-lib-dir ${ZIG_LIB_DIR} \
		--test-filter "exportAir"

.PHONY: release
release:
	time ${ZIG} build \
		-Ddebug-extensions=true \
		-Doptimize=ReleaseFast \
		-Duse-llvm=true \
		-Ddev=x86_64-linux \
		--zig-lib-dir ${ZIG_LIB_DIR} \
		--prefix zig-out-release \
		--summary all

.PHONY: incremental
incremental:
	${ZIG} build \
		-Ddebug-extensions=true \
		-Dno-lib \
		-Dno-bin \
		-Duse-llvm=false \
		-Ddev=x86_64-linux \
		--zig-lib-dir ${ZIG_LIB_DIR} \
		-fincremental \
		--watch

.PHONY: incremental-bin
incremental-bin:
	${ZIG} build \
		-Ddebug-extensions=true \
		-Dno-lib \
		-Duse-llvm=false \
		-Ddev=x86_64-linux \
		--zig-lib-dir ${ZIG_LIB_DIR} \
		-fincremental \
		--watch

# ./zig-out/bin/zig build-obj --verbose-air ./test.zig 2&> test.air
.PHONY: xxd
xxd:
	xxd -R always ./air_export.air.bin | less -R

.PHONY: analyze
analyze:
	cd ./analyzer && zig build run

.PHONY: test-integration
test-integration:
	${MAKE} test-unit
	${MAKE} build
	./zig-out/bin/zig build-obj ./analyzer/test.zig
	${MAKE} analyze
