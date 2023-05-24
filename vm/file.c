/* file.c: Implementation of memory backed file object (mmaped object). */

#include "vm/vm.h"
#include "threads/vaddr.h"
#include "threads/mmu.h"
#include "include/threads/malloc.h"

static bool file_backed_swap_in (struct page *page, void *kva);
static bool file_backed_swap_out (struct page *page);
static void file_backed_destroy (struct page *page);

/* DO NOT MODIFY this struct */
static const struct page_operations file_ops = {
	.swap_in = file_backed_swap_in,
	.swap_out = file_backed_swap_out,
	.destroy = file_backed_destroy,
	.type = VM_FILE,
};

/* The initializer of file vm */
void
vm_file_init (void) {
}

/* Initialize the file backed page */
bool
file_backed_initializer (struct page *page, enum vm_type type, void *kva) {
	/* Set up the handler */
	page->operations = &file_ops;

	struct file_page *file_page = &page->file;

	/* -- Project 3 -- */
	struct aux_struct *dummy = (struct aux_struct *)page->uninit.aux;

	file_page->file = dummy->vmfile;
	file_page->offset = dummy->ofs;
	file_page->read_byte = dummy->read_bytes;
	file_page->zero_byte = dummy->zero_bytes;
	file_page->type = type;

	if(file_read_at(dummy->vmfile , kva , dummy->read_bytes , dummy->ofs ) != dummy->read_bytes) {

		return false;
	}

	return true;
}

static bool
lazy_load_file(struct page *page, struct aux_struct *aux)
{
	/* -- Project 3 -- */
	if(file_read_at(page->file.file, page->frame->kva, page->file.read_byte,
					page->file.offset) != (int32_t) page->file.read_byte) {
		palloc_free_page(page->frame->kva);
		free(aux);
		return false;
	}
	memset(page->frame->kva + page->file.read_byte, 0, page->file.zero_byte);
	free(aux);

	return true;
}

/* Swap in the page by read contents from the file. */
static bool
file_backed_swap_in (struct page *page, void *kva) {
	struct file_page *file_page UNUSED = &page->file;
	if(file_read_at(file_page->file,kva ,file_page->read_byte, file_page->offset != (int) file_page->read_byte)){
		return false;
	}
	return true;
}

/* Swap out the page by writeback contents to the file. */
static bool
file_backed_swap_out (struct page *page) {
	struct file_page *file_page UNUSED = &page->file;
	if(pml4_is_dirty(thread_current()->pml4, page->va)) {
		pml4_set_dirty(thread_current()->pml4, page->va, false);
		file_write_at(page->file.file, page->va, page->file.read_byte, page->file.offset);
	}
	pml4_clear_page(thread_current()->pml4, page->va);
	page->frame = NULL;
	return true;
}

/* Destory the file backed page. PAGE will be freed by the caller. */
static void
file_backed_destroy (struct page *page) {
	struct file_page *file_page UNUSED = &page->file;

	if (page->frame) {
		palloc_free_page(page->frame->kva);
		free(page->frame);
	}
	pml4_clear_page(thread_current()->pml4, page->va);
	free(page);
}

/* 
 * offset 바이트에서 시작해 addr에 있는 프로세스의 가상 주소 공간에 fd로 열린 파일의 length 바이트 매핑
 * 전체 파일은 addr에서 시작하는 연속적인 가상 페이지에 매핑
 * 파일 길이가 PGSIZE의 배수가 아니면 매핑된 최종 페이지의 일부 바이트가 파일 끝을 넘어 삐져나옴
 * 페이지에 오류가 발생하면 이 바이트를 0으로 설정하고 페이지를 디스크에 다시 쓸 때 버림
 * 성공하면 이 함수는 파일이 매핑된 가상 주소를 반환한다
 * 
 * Linux에서는 addr이 NULL이면 커널은 매핑을 생성한 적절한 주소를 찾는다
 * 그래서 addr이 0이면 일부 Pintos 코드는 가상 페이지 0이 매핑되지 않았다고 가정, 실패함
 * length가 0일때도 mmap 실패해야 함.
 */
void *
do_mmap (void *addr, size_t length, int writable,
		struct file *file, off_t offset) {
	
	off_t read_size = file_length(file);

	void *va = addr;

	while (0 < read_size){
		struct aux_struct *temp_aux = (struct aux_struct*)malloc(sizeof(struct aux_struct));

        uint32_t read_bytes = read_size > PGSIZE ? PGSIZE : read_size;
		
		temp_aux->vmfile = file;
		temp_aux->ofs = offset;
		temp_aux->read_bytes = read_bytes;
		temp_aux->zero_bytes = PGSIZE - read_bytes;
		temp_aux->writable = writable;
		temp_aux->upage = va;
		
		if (!vm_alloc_page_with_initializer(VM_FILE, va, writable, lazy_load_file, temp_aux))
			return NULL;
		
		read_size -= read_bytes;
		va += PGSIZE;
		offset += read_bytes;
	}
	return addr;
}

/* Do the munmap */
void
do_munmap (void *addr) {
	
	struct page *page = spt_find_page(&thread_current()->spt, pg_round_down(addr));

	struct file *file = page->file.file;
	off_t read_size = file_length(file);

	while(page = spt_find_page(&thread_current()->spt, addr)) {
		if(page->file.file != file)
			return;
		
		if(pml4_is_dirty(thread_current()->pml4, addr)) {
			pml4_set_dirty(thread_current()->pml4, addr, false);
			file_write_at(page->file.file, addr, page->file.read_byte, page->file.offset);
		}
		addr += PGSIZE;
	}
}