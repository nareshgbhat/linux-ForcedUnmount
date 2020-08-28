/*
 * Copyright (C) 1995-2003 Russell King
 *               2001-2002 Keith Owens
 *     
 * Generate definitions needed by assembly language modules.
 * This code generates raw asm output which is post-processed to extract
 * and format the required data.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#include <linux/sched.h>
#include <linux/mm.h>
#include <asm/mach/arch.h>
#include <asm/thread_info.h>
#include <asm/memory.h>

/*
 * Make sure that the compiler and target are compatible.
 */
#if defined(__APCS_26__)
#error Sorry, your compiler targets APCS-26 but this kernel requires APCS-32
#endif
/*
 * GCC 2.95.1, 2.95.2: ignores register clobber list in asm().
 * GCC 3.0, 3.1: general bad code generation.
 * GCC 3.2.0: incorrect function argument offset calculation.
 * GCC 3.2.x: miscompiles NEW_AUX_ENT in fs/binfmt_elf.c
 *            (http://gcc.gnu.org/PR8896) and incorrect structure
 *	      initialisation in fs/jffs2/erase.c
 */
#if __GNUC__ < 2 || \
   (__GNUC__ == 2 && __GNUC_MINOR__ < 95) || \
   (__GNUC__ == 2 && __GNUC_MINOR__ == 95 && __GNUC_PATCHLEVEL__ != 0 && \
					     __GNUC_PATCHLEVEL__ < 3) || \
   (__GNUC__ == 3 && __GNUC_MINOR__ < 3)
#error Your compiler is too buggy; it is known to miscompile kernels.
#error    Known good compilers: 2.95.3, 2.95.4, 2.96, 3.3
#endif

/* Use marker if you need to separate the values later */

#define DEFINE(sym, val) \
        asm volatile("\n->" #sym " %0 " #val : : "i" (val))

#define BLANK() asm volatile("\n->" : : )

int main(void)
{
  DEFINE(TSK_ACTIVE_MM,		offsetof(struct task_struct, active_mm));
  BLANK();
  DEFINE(TI_FLAGS,		offsetof(struct thread_info, flags));
  DEFINE(TI_PREEMPT,		offsetof(struct thread_info, preempt_count));
  DEFINE(TI_ADDR_LIMIT,		offsetof(struct thread_info, addr_limit));
  DEFINE(TI_TASK,		offsetof(struct thread_info, task));
  DEFINE(TI_EXEC_DOMAIN,	offsetof(struct thread_info, exec_domain));
  DEFINE(TI_CPU,		offsetof(struct thread_info, cpu));
  DEFINE(TI_CPU_DOMAIN,		offsetof(struct thread_info, cpu_domain));
  DEFINE(TI_CPU_SAVE,		offsetof(struct thread_info, cpu_context));
  DEFINE(TI_USED_CP,		offsetof(struct thread_info, used_cp));
  DEFINE(TI_FPSTATE,		offsetof(struct thread_info, fpstate));
  DEFINE(TI_VFPSTATE,		offsetof(struct thread_info, vfpstate));
  DEFINE(TI_IWMMXT_STATE,	(offsetof(struct thread_info, fpstate)+4)&~7);
  BLANK();
#if __LINUX_ARM_ARCH__ >= 6
  DEFINE(MM_CONTEXT_ID,		offsetof(struct mm_struct, context.id));
  BLANK();
#endif
  DEFINE(VMA_VM_MM,		offsetof(struct vm_area_struct, vm_mm));
  DEFINE(VMA_VM_FLAGS,		offsetof(struct vm_area_struct, vm_flags));
  BLANK();
  DEFINE(VM_EXEC,	       	VM_EXEC);
  BLANK();
  DEFINE(PAGE_SZ,	       	PAGE_SIZE);
  DEFINE(VIRT_OFFSET,	       	PAGE_OFFSET);
  BLANK();
  DEFINE(SYS_ERROR0,		0x9f0000);
  BLANK();
  DEFINE(SIZEOF_MACHINE_DESC,	sizeof(struct machine_desc));
  return 0; 
}
