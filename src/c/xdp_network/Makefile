BPF_CLANG ?= clang
CFLAGS += -O2 -g -Wall

all: xdp_tail_pipeline.o

%.o: %.c
	$(BPF_CLANG) -target bpf -D__TARGET_ARCH_x86 -O2 -g -c $< -o $@

clean:
	rm -f *.o
