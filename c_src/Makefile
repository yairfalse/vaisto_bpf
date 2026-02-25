# Only build on Linux — the BPF loader requires libbpf + kernel support
UNAME_S := $(shell uname -s)
PRIV_DIR ?= $(MIX_APP_PATH)/priv

ifeq ($(UNAME_S),Linux)

CFLAGS  = -Wall -Wextra -O2 -std=c11
LDFLAGS = -lbpf -lelf -lz

all: $(PRIV_DIR)/bpf_loader

$(PRIV_DIR)/bpf_loader: bpf_loader.c
	@mkdir -p $(PRIV_DIR)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(PRIV_DIR)/bpf_loader

else

all:
	@echo "Skipping bpf_loader build (not Linux)"

clean:
	@echo "Nothing to clean (not Linux)"

endif

.PHONY: all clean
