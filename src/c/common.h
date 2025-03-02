
#ifndef COMMON_HEADER_H
#define COMMON_HEADER_H

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

/* Macro concatenation */
#define ___CAT_1(a)			a
#define __CAT_1(a)			___CAT_1(a)
#define EVAL_CAT_1(a)			__CAT_1(a)

#define ___CAT_2(a, b)			a##b
#define __CAT_2(a, b)			___CAT_2(a, b)
#define EVAL_CAT_2(a, b)		__CAT_2(a, b)

#define ___CAT_3(a, b, c)		a##b##c
#define __CAT_3(a, b, c)		___CAT_3(a, b, c)
#define EVAL_CAT_3(a, b, c)		__CAT_3(a, b, c)

#define ___CAT_4(a, b, c, d)		a##b##c##d
#define __CAT_4(a, b, c, d)		___CAT_4(a, b, c, d)
#define EVAL_CAT_4(a, b, c, d)		__CAT_4(a, b, c, d)

#define ___CAT_5(a, b, c, d, e)		a##b##c##d##e
#define __CAT_5(a, b, c, d, e)		___CAT_5(a, b, c, d, e)
#define EVAL_CAT_5(a, b, c, d, e)	__CAT_5(a, b, c, d, e)

#define ___CAT_6(a, b, c, d, e, f)	a##b##c##d##e##f
#define __CAT_6(a, b, c, d, e, f)	___CAT_6(a, b, c, d, e, f)
#define EVAL_CAT_6(a, b, c, d, e, f)	__CAT_6(a, b, c, d, e, f)

#define __stringify(X)			#X
#define stringify(X)			__stringify(X)


/* New API for printing into the trace pipe
 * ========================================
 */
#define PRINT_LEVEL_EMERG		0
#define PRINT_LEVEL_ALERT		1
#define PRINT_LEVEL_CRIT		2
#define PRINT_LEVEL_ERR			3
#define PRINT_LEVEL_WARNING		4
#define PRINT_LEVEL_NOTICE		5
#define PRINT_LEVEL_INFO		6
#define PRINT_LEVEL_DEBUG		7

#ifndef PRINT_LEVEL
#define PRINT_LEVEL			PRINT_LEVEL_WARNING
#endif

/* Introduce new API for printing on trace pipe
 *
 * The new set of APIs introduced allows to differentiate the printing
 * behavior based on the priority to be assigned to the printed message.
 *
 * Below are several predefined priorities that are conceptually associated
 * with some types of events such as EMERG, ERR, WARNING, etc.
 * Each priority is expressed with a positive integer.
 *
 * NOTE: the highest priority corresponds to the value 0 (EMERG).
 * Therefore, the lower the priority, the higher its associated integer
 * value.
 *
 * EMERG     0  | Higher Priority
 * ALERT     1  |
 * CRIT      2  |
 * ERR       3  |
 * WARNING   4  |
 * NOTICE    5  |
 * INFO      6  |
 * DEBUG     7  v Lower Priority
 *
 * Within an eBPF program, it is possible to set the PRINT_LEVEL macro to one
 * of the priority values shown above; otherwise the PRINT_LEVEL is the
 * default value PRINT_LEVEL_WARNING.
 *
 * As a result, all print messages that have a priority greater than or
 * equal to PRINT_LEVEL will be shown on the trace pipe.
 */

#define __HELPER_PRINT(LEVEL, ...)					\
do {									\
	/* since those values are macros and values never change,	\
	 * the optimizer remove the if :-)				\
	 */								\
	if (EVAL_CAT_2(PRINT_LEVEL_, LEVEL) <= PRINT_LEVEL)		\
		bpf_printk(stringify(LEVEL)": " __VA_ARGS__);		\
} while (0)

/* Unified print helper functions for HIKe eBPF Programs */
#define pr_emerg(...)	__HELPER_PRINT(EMERG, __VA_ARGS__)
#define pr_alert(...)	__HELPER_PRINT(ALERT, __VA_ARGS__)
#define pr_crit(...)	__HELPER_PRINT(CRIT, __VA_ARGS__)
#define pr_err(...)	__HELPER_PRINT(ERR, __VA_ARGS__)
#define pr_warn(...)	__HELPER_PRINT(WARNING, __VA_ARGS__)
#define pr_notice(...)	__HELPER_PRINT(NOTICE, __VA_ARGS__)
#define pr_info(...)	__HELPER_PRINT(INFO, __VA_ARGS__)
#define pr_debug(...)	__HELPER_PRINT(DEBUG, __VA_ARGS__)


/* Memory facilities
 * =================
 */
#ifndef memset
#define memset(dest, val, n) __builtin_memset((dest), (val), (n))
#endif

#ifndef memcpy
#define memcpy(dest, src, n)   __builtin_memcpy((dest), (src), (n))
#endif

#endif
