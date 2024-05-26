ROOT_DIR:=$(strip $(dir $(realpath $(lastword $(MAKEFILE_LIST)))))

default: execute

.PHONY: platform
platform:
	cargo +risc0 rustc -p zkvm-platform --target riscv32im-risc0-zkvm-elf --lib --crate-type staticlib --release --target-dir ./guest/out/platform

.PHONY: guest
guest: platform
	# TODO pull toolchain into project
	/tmp/riscv32im-osx-arm64/bin/riscv32-unknown-elf-gcc -nostartfiles ./guest/main.c -o ./guest/out/main -L/Users/austinabell/development/austinabell/cr0//guest/out/platform/riscv32im-risc0-zkvm-elf/release -lzkvm_platform -T ./guest/riscv32im-risc0-zkvm-elf.ld

.PHONY: execute
execute: guest
	RISC0_DEV_MODE=true cargo run

.PHONY: prove
prove: guest
	cargo run
