#include "userprog/syscall.h"
#include <stdio.h>
#include "include/lib/kernel/stdio.h"
#include "lib/user/syscall.h"
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"
#include "userprog/process.h"
#include "filesys/filesys.h"
#include "include/filesys/file.h"

// 유저 프로세스가 일부 커널 기능에 접근하려고 할때마다 시스템 콜이 호출된다.
// 이게 시스템 콜 핸들러의 기본 구조
// 현재 상태에서는 이때 단지 메세지를 출력하고 유저 프로세스를 종료시키게 되어있다. 
// 시스템 콜이 필요로 하는 다른 일을 수행하는 코드를 수행

void syscall_entry (void);
void syscall_handler (struct intr_frame *);
void check_user(const void *);
void check_user_buffer(const void *, size_t);
bool sys_create(const char *, unsigned int);
int sys_open (const char *);
bool check_fd_table(int);
void sys_close(int );
void sys_halt (void);
int sys_write(int , const void *, unsigned);
void sys_exit (int);
tid_t sys_fork (const char *, struct intr_frame *);
tid_t sys_exec (const char*);

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void
syscall_init (void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) {
	// TODO: Your implementation goes here.

	switch (f->R.rax)
	{
		case SYS_HALT:
			sys_halt();
			break;
		case SYS_EXEC:
			sys_exec(f->R.rdi);
		case SYS_OPEN:
			f->R.rax = sys_open(f->R.rdi);
			break;
		case SYS_CREATE:
			f->R.rax = sys_create(f->R.rdi, f->R.rsi);
			break;
		case SYS_CLOSE:
			sys_close(f->R.rdi);
			break;
		case SYS_FORK:
			f->R.rax = sys_fork(f->R.rdi, f);
			break;
		case SYS_WRITE:
			f->R.rax = sys_write(f->R.rdi, f->R.rsi, f->R.rdx);	
			break;
		case SYS_EXIT:
			sys_exit(f->R.rdi);
			break;
		default:
			sys_exit(f->R.rdi);
			break;
	}

	// printf ("system call!\n");
	//
	
}


// 유저 주소 체크 함수 입니다.
void 
check_user(const void *uaddr){
	if (uaddr == NULL || !is_user_vaddr(uaddr) ||
		pml4_get_page(thread_current()->pml4, uaddr) == NULL){
		sys_exit(-1);
	}
}

// 유저 버퍼 체크 함수
void
check_user_buffer(const void *uaddr, size_t size) {
	for (size_t i = 0; i < size; i++){
		check_user((const uint8_t *)uaddr + i);
	}
}

bool 
sys_create(const char *file, unsigned int initial_size) {
	check_user(file);
	return filesys_create(file, initial_size);
}

int
sys_open (const char *file){
	check_user(file);

	struct file *f = filesys_open(file);

    if (f == NULL) return -1;
	
	struct thread *curr = thread_current();

	for (int fd = FD_START; fd < FD_MAX; fd++) {
		if (curr->fd_table[fd] == NULL) {
			curr->fd_table[fd] = f;
			return fd;
		}
	}
	sys_exit(-1); 
}


bool 
check_fd_table(int fd){
	if ((FD_START <= fd) && (fd < FD_MAX) 
		&& (thread_current()->fd_table[fd] != NULL))
		return true;
	return false;
}

void 
sys_close(int fd) {
	if(check_fd_table(fd))
		return;

	struct file *f = thread_current()->fd_table[fd];

    file_close(f);
    thread_current()->fd_table[fd] = NULL;
}




void 
sys_halt (void){
	power_off();
}

int
sys_write(int fd, const void *buffer, unsigned size){
	check_user_buffer(buffer, size); // 유저 버퍼 체크

	if(fd == 1){
		putbuf((const char *)buffer, (size_t)size);
		return size;
	}

	return -1;
}

void 
sys_exit (int status){
	struct thread *cur = thread_current ();
	
	printf ("%s: exit(%d)\n", cur->name, status); 
	thread_exit ();
}

tid_t
sys_fork (const char *thread_name, struct intr_frame *if_ UNUSED){
	return process_fork(thread_name, if_);
}

tid_t
sys_exec (const char *cmd_line){
	if (process_exec(cmd_line) == -1){
		return PID_ERROR;
	}

	return thread_current()->tid;
}


