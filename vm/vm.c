/* vm.c: Generic interface for virtual memory objects. */

#include "threads/malloc.h"
#include "vm/vm.h"
#include "vm/inspect.h"
#include "lib/kernel/hash.h"
#include "threads/vaddr.h"
#include "threads/mmu.h"
#include "threads/vaddr.h"

/* Initializes the virtual memory subsystem by invoking each subsystem's
 * intialize codes. */
void
vm_init (void) {
	vm_anon_init ();
	vm_file_init ();
#ifdef EFILESYS  /* For project 4 */
	pagecache_init ();
#endif
	register_inspect_intr ();
	/* DO NOT MODIFY UPPER LINES. */
	/* TODO: Your code goes here. */
}
static void
frame_init(struct frame *frame, const void *addr)
{
	frame->kva = addr;
	frame->page = NULL;
	// frame->accessed = false;
	// frame->dirty = false;
}
/* Get the type of the page. This function is useful if you want to know the
 * type of the page after it will be initialized.
 * This function is fully implemented now. */
enum vm_type
page_get_type (struct page *page) {
	int ty = VM_TYPE (page->operations->type);
	switch (ty) {
		case VM_UNINIT:
			return VM_TYPE (page->uninit.type);
		default:
			return ty;
	}
}

/* Helpers */
static struct frame *vm_get_victim (void);
static bool vm_do_claim_page (struct page *page);
static struct frame *vm_evict_frame (void);

/* Create the pending page object with initializer. If you want to create a
 * page, do not create it directly and make it through this function or
 * `vm_alloc_page`. */
bool
vm_alloc_page_with_initializer (enum vm_type type, void *upage, bool writable,
		vm_initializer *init, void *aux) {

	ASSERT (VM_TYPE(type) != VM_UNINIT)

	bool success = false;
	struct supplemental_page_table *spt = &thread_current()->spt;
	
	/* Check wheter the upage is already occupied or not. */
	if (spt_find_page (spt, upage) == NULL) {
		/* TODO: Create the page, fetch the initialier according to the VM type,
		 * TODO: and then create "uninit" page struct by calling uninit_new. You
		 * TODO: should modify the field after calling the uninit_new. */
		struct page *p = (struct page *)malloc(sizeof(struct page));

		switch(VM_TYPE(type)) {
			case VM_ANON:
				uninit_new(p, pg_round_down(upage), init, type, aux, anon_initializer);
				break;
			case VM_FILE:
				uninit_new(p, pg_round_down(upage), init, type, aux, file_backed_initializer);
				break;
		}
		p->writable = writable;
		/* TODO: Insert the page into the spt. */
		success = spt_insert_page(spt, p);
		
		return success;
	}
err:
	return success;
}

/* Find VA from spt and return page. On error, return NULL. */
struct page *
spt_find_page (struct supplemental_page_table *spt UNUSED, void *va UNUSED) {
	/* TODO: Fill this function. */
	struct page page;
	page.va = pg_round_down(va);
	struct hash_elem *e = hash_find (&spt->spt_hash_table, &(page.hash_elem));

	return e ? hash_entry(e, struct page, hash_elem) : NULL;
}
/* 해시 요소들 비교 */
bool
hash_less (const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED)
{
	const struct page *a_p = hash_entry(a, struct page, hash_elem);
	const struct page *b_p = hash_entry(b, struct page, hash_elem);

	return a_p->va < b_p->va;
}

unsigned
hash_func (const struct hash_elem *a, void *aux UNUSED)
{
	const struct page *p = hash_entry(a, struct page, hash_elem);
	return hash_bytes (&p->va, sizeof(p->va));
}
/* Insert PAGE into spt with validation. */
bool
spt_insert_page (struct supplemental_page_table *spt UNUSED,
		struct page *page UNUSED) {
	/* TODO: Fill this function. */ 
	int success = false;
	if(hash_insert(&(spt->spt_hash_table), &(page->hash_elem)) == NULL) {
		success = true;
	}
	return success;
}

void
spt_remove_page (struct supplemental_page_table *spt, struct page *page) {
	vm_dealloc_page (page);
	return true;
}

/* Get the struct frame, that will be evicted. */
static struct frame *
vm_get_victim (void) {
	struct frame *victim = NULL;
	 /* TODO: The policy for eviction is up to you. */
	struct thread * curr = thread_current();
	struct hash hash = curr->spt.spt_hash_table;
	struct hash_iterator *iter;
	hash_first(iter,&hash);
	while(hash_next(iter)) {

		struct page * cur_page = hash_entry(iter->elem, struct page ,hash_elem);

		if(pml4_is_accessed(curr->pml4, cur_page->va)) {
			pml4_set_accessed(curr->pml4, cur_page->va, false);
			continue;
		}
		if(cur_page->frame == NULL) continue;
		
		if (page_get_type(cur_page) == VM_FILE)
		{
			victim = cur_page->frame;
			break;
		}
		else if (page_get_type(cur_page) == VM_ANON)
		{
			victim = cur_page->frame;
			break;
		}
	}
	return victim;
}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
static struct frame *
vm_evict_frame (void) {
	struct frame *victim UNUSED = vm_get_victim ();
	/* TODO: swap out the victim and return the evicted frame. */
	if(victim != NULL){
		struct thread *curr = thread_current();
		struct page *victim_page = victim->page;

		swap_out(victim_page);
	}
	return victim;
}

/* palloc() and get frame. If there is no available page, evict the page
 * and return it. This always return valid address. That is, if the user pool
 * memory is full, this function evicts the frame to get the available memory
 * space.*/
static struct frame *
vm_get_frame (void) {
	/* TODO: Fill this function. */
	struct frame *frame = (struct frame*)malloc(sizeof(struct frame));
	frame->kva = palloc_get_page(PAL_USER);
	frame->page = NULL;

	if (frame->kva == NULL) {
		// PANIC("todo");
		frame = NULL;	
	} 

	ASSERT (frame != NULL);
	ASSERT (frame->page == NULL);
	return frame;
}

/* Growing the stack. */
static void
vm_stack_growth (void *addr UNUSED) {
	/* -- Project 3 -- */
	vm_alloc_page(VM_ANON | VM_MARKER_0, addr, true);
}

/* Handle the fault on write_protected page */
static bool
vm_handle_wp (struct page *page UNUSED) {
}

/* Return true on success */
bool
vm_try_handle_fault (struct intr_frame *f UNUSED, void *addr UNUSED,
		bool user UNUSED, bool write UNUSED, bool not_present UNUSED) {
	struct supplemental_page_table *spt UNUSED = &thread_current ()->spt;
	/* -- Project 3 -- */
	struct page *page = spt_find_page(spt, addr);
	/* TODO: Validate the fault */
	/* TODO: Your code goes here */
	if(is_kernel_vaddr(addr))
		return false;
	
	uint16_t STACK_LIMIT = USER_STACK - (1<<20);
	uint64_t limit = f->rsp - 8;

	if(page == NULL && limit == addr) {
		if(f->rsp > STACK_LIMIT && USER_STACK > f->rsp) {
			while(limit <= thread_current()->stack_bottom) {
				vm_stack_growth(thread_current()->stack_bottom - 8);
				thread_current()->stack_bottom -= PGSIZE;
			}
			return true;
		}
		return false;
	}
	if(page && not_present)
		return vm_do_claim_page(page);
	
	return false;
}

/* Free the page.
 * DO NOT MODIFY THIS FUNCTION. */
void
vm_dealloc_page (struct page *page) {
	destroy (page);
	free (page);
}

/* Claim the page that allocate on VA. */
bool
vm_claim_page (void *va UNUSED) {
	/* TODO: Fill this function */
	struct page *page = spt_find_page (&thread_current ()->spt, va);
	if (!page) return false;

	return vm_do_claim_page (page);
}

/* Claim the PAGE and set up the mmu. */
static bool
vm_do_claim_page (struct page *page) {
	struct frame *frame = vm_get_frame ();
	
	if(frame == NULL) {
		frame = vm_evict_frame();
	}

	/* Set links */
	frame->page = page;
	page->frame = frame;

	/* TODO: Insert page table entry to map page's VA to frame's PA. */
	pml4_set_page(thread_current()->pml4, page->va, frame->kva, page->writable);
	
	return swap_in (page, frame->kva);
}

/* Initialize new supplemental page table */
void
supplemental_page_table_init (struct supplemental_page_table *spt UNUSED)
{
	hash_init(&spt->spt_hash_table, hash_func, hash_less, NULL);
}
/* hash function; spt_src의 해쉬 테이블에서 모든 페이지 구조체를 spt_dst
 * 테이블로 복사. uninit, anon, file 전부 다 uninit으로 */
void
copy_page(struct hash_elem *e, void *aux)
{
	struct page* page = hash_entry(e, struct page, hash_elem);
	vm_alloc_page(page->uninit.type, page->va, page->writable);
	if(page->frame) {
		struct page *child = spt_find_page(&thread_current()->spt, page->va);
		child->frame = vm_get_frame();
		memcpy(child->frame->kva, page->frame->kva, PGSIZE);
		child->frame->page = child;
		pml4_set_page(thread_current()->pml4, child->va, child->frame->kva, child->writable);
	}
}
/* Copy supplemental page table from src to dst */
bool
supplemental_page_table_copy (struct supplemental_page_table *dst UNUSED,
		struct supplemental_page_table *src UNUSED)
{
	hash_apply(&src->spt_hash_table, copy_page);
	return true;
}
void
kill_page(struct hash_elem *e, void *aux)
{
	struct page *page = hash_entry(e, struct page, hash_elem);
	destroy(page);
}
/* Free the resource hold by the supplemental page table */
void
supplemental_page_table_kill (struct supplemental_page_table *spt UNUSED) {
	/* TODO: Destroy all the supplemental_page_table hold by thread and
	 * TODO: writeback all the modified contents to the storage. */
	hash_clear(&spt->spt_hash_table, kill_page);
}