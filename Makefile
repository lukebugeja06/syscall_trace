# Makefile – syscall_trace eBPF project
# Requires: clang, llvm, libbpf-dev, bpftool
#
# Usage:
#   make                      – build everything
#   make clean                – remove build artefacts
#   make run                  – build and run (traces all PIDs, needs root)
#   make run ARGS="1234 5678" – build and run with PID filter
#   make install              – install binary to /usr/local/bin

# ── Toolchain ─────────────────────────────────────────────────────────────────
CC      := clang
BPFTOOL := bpftool

# ── Paths ─────────────────────────────────────────────────────────────────────
OUTPUT  := .output
VMLINUX := $(OUTPUT)/vmlinux.h

# ── Flags ─────────────────────────────────────────────────────────────────────
LIBBPF_CFLAGS  := $(shell pkg-config --cflags libbpf 2>/dev/null || echo "-I/usr/include/bpf")
LIBBPF_LDFLAGS := $(shell pkg-config --libs   libbpf 2>/dev/null || echo "-lbpf")

# Userspace flags: include both . (for syscall_trace.h) and OUTPUT (for skel.h)
CFLAGS := -g -Wall -Wextra -I. -I$(OUTPUT) $(LIBBPF_CFLAGS)

# BPF kernel-side flags: -I. must come before -I$(OUTPUT) so the project's
# syscall_trace.h is found first; -I$(OUTPUT) provides the generated vmlinux.h
BPF_CFLAGS := \
    -g                      \
    -O2                     \
    -target bpf             \
    -D__TARGET_ARCH_x86     \
    -I.                     \
    -I$(OUTPUT)             \
    $(LIBBPF_CFLAGS)

# ── Targets ───────────────────────────────────────────────────────────────────
.PHONY: all clean run install

all: syscall_trace

# 1. Create output directory
$(OUTPUT):
	mkdir -p $(OUTPUT)

# 2. Generate vmlinux.h from the running kernel's BTF (always reflects current kernel)
$(VMLINUX): | $(OUTPUT)
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

# 3. Compile BPF object
$(OUTPUT)/syscall_trace.bpf.o: syscall_trace.bpf.c syscall_trace.h $(VMLINUX)
	$(CC) $(BPF_CFLAGS) -c $< -o $@

# 4. Generate BPF skeleton header
$(OUTPUT)/syscall_trace.skel.h: $(OUTPUT)/syscall_trace.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

# 5. Compile and link userspace binary
syscall_trace: syscall_trace.c syscall_trace.h $(OUTPUT)/syscall_trace.skel.h
	$(CC) $(CFLAGS) $< -o $@ $(LIBBPF_LDFLAGS) -lelf -lz

# ── Helpers ───────────────────────────────────────────────────────────────────
clean:
	rm -rf $(OUTPUT) syscall_trace

run: all
	sudo ./syscall_trace $(ARGS)

install: all
	sudo cp syscall_trace /usr/local/bin/syscall_trace
	sudo chmod 755 /usr/local/bin/syscall_trace
	@echo "Installed to /usr/local/bin/syscall_trace"
