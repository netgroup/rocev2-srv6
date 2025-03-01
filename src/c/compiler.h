
#ifndef _COMPILER_H
#define _COMPILER_H

#ifndef barrier
#define barrier()		__asm__ __volatile__("": : :"memory")
#endif

#ifndef barrier_data
/*
 * This version is i.e. to prevent dead stores elimination on @ptr
 * where gcc and llvm may behave differently when otherwise using
 * normal barrier(): while gcc behavior gets along with a normal
 * barrier(), llvm needs an explicit input variable to be assumed
 * clobbered. The issue is as follows: while the inline asm might
 * access any memory it wants, the compiler could have fit all of
 * @ptr into memory registers instead, and since @ptr never escaped
 * from that, it proved that the inline asm wasn't touching any of
 * it. This version works well with both compilers, i.e. we're telling
 * the compiler that the inline asm absolutely may see the contents
 * of @ptr. See also: https://llvm.org/bugs/show_bug.cgi?id=15495
 */
# define barrier_data(ptr) 	__asm__ __volatile__("": :"r"(ptr) :"memory")
#endif

#ifndef build_bug_on
#define build_bug_on(E)		((void)sizeof(char[1 - 2*!!(E)]))
#endif

#ifndef likely
#define likely(x)		__builtin_expect(!!(x), 1)
#endif

#ifndef unlikely
#define unlikely(x)		__builtin_expect(!!(x), 0)
#endif

#ifndef __maybe_unused
#define __maybe_unused		__attribute__((__unused__))
#endif

#ifndef __READ_ONCE
#define __READ_ONCE(X)		(*(volatile typeof(X) *)&X)
#endif

#ifndef __WRITE_ONCE
#define __WRITE_ONCE(X, V)	(*(volatile typeof(X) *)&X) = (V)
#endif

/* {READ,WRITE}_ONCE() with verifier workaround via (bpf_)barrier(). */

#ifndef READ_ONCE
#define READ_ONCE(X)						\
({								\
	typeof(X) __val = __READ_ONCE(X);			\
	barrier();						\
	__val;							\
})
#endif

#ifndef WRITE_ONCE
#define WRITE_ONCE(X, V)					\
({								\
	typeof(X) __val = (V);					\
	__WRITE_ONCE(X, __val);					\
	barrier();						\
	__val;							\
})
#endif

/* relax_verifier is a dummy helper call to introduce a pruning checkpoint to
 * help relax the verifier to avoid reaching complexity limits on older
 * kernels.
 */
static __always_inline void relax_verifier(void)
{
#ifndef HAVE_LARGE_INSN_LIMIT
       volatile int __maybe_unused id = bpf_get_smp_processor_id();
#endif
}

#endif
