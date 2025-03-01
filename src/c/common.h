
#ifndef COMMON_HEADER_H
#define COMMON_HEADER_H

#ifdef DEBUG
#define BPF_PRINTK_DEBUG(...)		\
do {					\
	bpf_printk(__VA_ARGS__);	\
} while(0)
#else
#define BPF_PRINTK_DEBUG(...)		\
do {					\
	(void)(1);			\
} while(0)
#endif

#ifndef memset
#define memset(dest, val, n) __builtin_memset((dest), (val), (n))
#endif

#ifndef memcpy
#define memcpy(dest, src, n)   __builtin_memcpy((dest), (src), (n))
#endif

#endif // COMMON_HEADER_H
