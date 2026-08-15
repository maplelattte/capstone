CLANG ?= clang
BPFTOOL ?= bpftool
CFLAGS ?= -O2 -g -Wall -I. -Ibuild

SRC_DIR = src
USER_DIR = user
BUILD_DIR = build

all: vmlinux.h $(BUILD_DIR)/freeze_kern.o $(BUILD_DIR)/freeze_kern.skel.h $(BUILD_DIR)/supervisor

vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

$(BUILD_DIR)/freeze_kern.o: $(SRC_DIR)/freeze_kern.c $(SRC_DIR)/maps.h vmlinux.h
	mkdir -p $(BUILD_DIR)
	$(CLANG) $(CFLAGS) -target bpf -D__TARGET_ARCH_x86 -c $< -o $@

$(BUILD_DIR)/freeze_kern.skel.h: $(BUILD_DIR)/freeze_kern.o
	$(BPFTOOL) gen skeleton $< > $@

$(BUILD_DIR)/supervisor: $(USER_DIR)/supervisor.c $(SRC_DIR)/maps.h $(BUILD_DIR)/freeze_kern.skel.h
	mkdir -p $(BUILD_DIR)
	gcc $(CFLAGS) $< -o $@ -lbpf

clean:
	rm -rf $(BUILD_DIR) vmlinux.h /sys/fs/bpf/freeze_prog /sys/fs/bpf/alert_ringbuf /sys/fs/bpf/proc_state_map /sys/fs/bpf/tuple_map

.PHONY: all clean
