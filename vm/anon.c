/* anon.c: Implementation of page for non-disk image (a.k.a. anonymous page). */

#include "vm/vm.h"
#include "devices/disk.h"

/* DO NOT MODIFY BELOW LINE */
static struct disk *swap_disk;
static bool anon_swap_in (struct page *page, void *kva);
static bool anon_swap_out (struct page *page);
static void anon_destroy (struct page *page);

/* DO NOT MODIFY this struct */
static const struct page_operations anon_ops = {
	.swap_in = anon_swap_in,
	.swap_out = anon_swap_out,
	.destroy = anon_destroy,
	.type = VM_ANON,
};

/* Initialize the data for anonymous pages */
void
vm_anon_init (void) {
	/* TODO: Set up the swap_disk. */
	/* -- Project 3 -- */
	swap_disk = disk_get(1, 1);
	// disk sector 크기 = 512bytes
	// page 크기 = 4KB = 512 * 8 bytes = disk sector * 8
	thread_current()->disk_table = bitmap_create(disk_size(swap_disk) / 8);
}

/* Initialize the file mapping */
bool
anon_initializer (struct page *page, enum vm_type type, void *kva) {
	/* Set up the handler */
	page->operations = &anon_ops;

	struct anon_page *anon_page = &page->anon;
}

/* Swap in the page by read contents from the swap disk. */
static bool
anon_swap_in (struct page *page, void *kva) {
	struct anon_page *anon_page = &page->anon;
	/* -- Project 3 -- */
	struct disk *disk = thread_current()->disk_table;
	size_t sector_slot = page->anon.swap_slot;
	disk_read(disk, sector_slot, kva);
	bitmap_set(disk, sector_slot, false);

	return true;
}

/* Swap out the page by writing contents to the swap disk. */
static bool
anon_swap_out (struct page *page) {
	struct anon_page *anon_page = &page->anon;
	/* -- Project 3 -- */
	/* 테이블 순회해서 swap_slot이 1이 아닌것을 찾음 */
	struct disk *disk = thread_current()->disk_table;

	size_t empty_slot = bitmap_scan(disk, 0, 1, false);

	if(empty_slot == BITMAP_ERROR) {
		PANIC("empty_slot, BITMAP_ERROR");
	}
	page->anon.swap_slot = empty_slot;
	disk_write(disk, empty_slot, page->frame->kva);
	bitmap_set(disk, empty_slot, true);
	
	if(page->frame) {
		palloc_free_page(page->frame->kva);
	}
	pml4_clear_page(thread_current()->pml4, page->va);
	
	return true;
}

/* Destroy the anonymous page. PAGE will be freed by the caller. */
static void
anon_destroy (struct page *page) {
	struct anon_page *anon_page = &page->anon;
	if(page->frame) {
		palloc_free_page(page->frame->kva);
		free(page->frame);
	}
	pml4_clear_page(thread_current()->pml4, page->va);
	free(page);
}
