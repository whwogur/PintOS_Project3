#include "userprog/tss.h"
#include <debug.h>
#include <stddef.h>
#include "userprog/gdt.h"
#include "threads/thread.h"
#include "threads/palloc.h"
#include "threads/vaddr.h"
#include "intrinsic.h"

/* The Task-State Segment (TSS).
 *
 *  Instances of the TSS, an x86-64 specific structure, are used to
 *  define "tasks", a form of support for multitasking built right
 *  into the processor.  However, for various reasons including
 *  portability, speed, and flexibility, most x86-64 OSes almost
 *  completely ignore the TSS.  We are no exception.
 *
 *  Unfortunately, there is one thing that can only be done using
 *  a TSS: stack switching for interrupts that occur in user mode.
 *  When an interrupt occurs in user mode (ring 3), the processor
 *  consults the rsp0 members of the current TSS to determine the
 *  stack to use for handling the interrupt.  Thus, we must create
 *  a TSS and initialize at least these fields, and this is
 *  precisely what this file does.
 *
 *  When an interrupt is handled by an interrupt or trap gate
 *  (which applies to all interrupts we handle), an x86-64 processor
 *  works like this:
 *
 *    - If the code interrupted by the interrupt is in the same
 *      ring as the interrupt handler, then no stack switch takes
 *      place.  This is the case for interrupts that happen when
 *      we're running in the kernel.  The contents of the TSS are
 *      irrelevant for this case.
 *
 *    - If the interrupted code is in a different ring from the
 *      handler, then the processor switches to the stack
 *      specified in the TSS for the new ring.  This is the case
 *      for interrupts that happen when we're in user space.  It's
 *      important that we switch to a stack that's not already in
 *      use, to avoid corruption.  Because we're running in user
 *      space, we know that the current process's kernel stack is
 *      not in use, so we can always use that.  Thus, when the
 *      scheduler switches threads, it also changes the TSS's
 *      stack pointer to point to the new thread's kernel stack.
 *      (The call is in schedule in thread.c.) */

/* Kernel TSS. */
struct task_state *tss;
/* TSS는 선점형 (preemptive) 스케줄러가 Task switching을 실행할 때
 * 기존에 실행중인 태스크의 상태를 보존하고 있다가, 이후에 다시 CPU를 선점하게
 * 되었을 때 보존된 태스크의 상태를 복구 시키기 위한 영역. 사용자 프로세스에서
 * 시스템 콜을 호출하면 인터럽트 핸들러로 들어가게 되는데, 이 때 커널의 스택포인터를 찾아
 * 거기에 이제까지 사용자 프로세스에서 진행했던 작업을 저장해 둔다. 커널 스택을 찾는데 드는
 * 오버헤드를 줄이기 위한 용도로 사용 */
void
tss_init (void) {
	/* Our TSS is never used in a call gate or task gate, so only a
	 * few fields of it are ever referenced, and those are the only
	 * ones we initialize. */
	tss = palloc_get_page (PAL_ASSERT | PAL_ZERO);
	tss_update (thread_current ());
}

/* Returns the kernel TSS. */
struct task_state *
tss_get (void) {
	ASSERT (tss != NULL);
	return tss;
}

/* Sets the ring 0 stack pointer in the TSS to point to the end
 * of the thread stack. */
void
tss_update (struct thread *next) {
	ASSERT (tss != NULL);
	tss->rsp0 = (uint64_t) next + PGSIZE;
}
