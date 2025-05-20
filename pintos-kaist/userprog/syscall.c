#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"

void syscall_entry (void);
void syscall_handler (struct intr_frame *);

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
	printf ("system call!\n");
	thread_exit ();

	uint64_t syscall_n = f->R.rax;

	
	switch(syscall_n)
	{
		case 0:
		{
			sys_halt();
			break;
		}

		case 1:
		{
			sys_exit(f->R.rdi);
			break;
		}

		case 2:
		{
			f->R.rax = sys_fork(f->R.rdi);
			break;
		}

		case 3:
		{
			f->R.rax = sys_exec(f->R.rdi);
			break;
		}

		case 4:
		{
			f->R.rax = sys_wait(f->R.rdi);
			break;
		}

		case 5:
		{
			f->R.rax = sys_create(f->R.rdi, f->R.rsi);
			break;
		}

		case 6:
		{
			f->R.rax = sys_remove(f->R.rdi);
			break;
		}

		case 7:
		{
			f->R.rax = sys_open(f->R.rdi);
			break;
		}

		case 8:
		{
			f->R.rax = sys_filesize(f->R.rdi);
			break;
		}

		case  9:
		{
			f->R.rax = sys_read(f->R.rdi, f->R.rsi, f->R.rdx);
			break;
		}

		case 10:
		{
			f->R.rax = sys_write(f->R.rdi, f->R.rsi, f->R.rdx);
			break;
		}

		case 11:
		{
			sys_seek(f->R.rdi, f->R.rsi);
			break;
		}

		case 12:
		{
			f->R.rax = sys_tell(f->R.rdi);
			break;
		}

		case 13:
		{
			sys_close(f->R.rdi);
			break;
		}

		default:
		{
			thread_exit();
			break;
		}
	}
}

void
sys_halt(void) {
	power_off();
	NOT_REACHED ();
}

void
sys_exit(int status) {
	thread_exit();
	NOT_REACHED ();
}

pid_t
sys_fork (const char *thread_name){
	return load()
}

int
sys_exec (const char *file) {
	return (pid_t) syscall1 (SYS_EXEC, file);
}

int
sys_wait (pid_t pid) {
	return syscall1 (SYS_WAIT, pid);
}

bool
sys_create (const char *file, unsigned initial_size) {
	return syscall2 (SYS_CREATE, file, initial_size);
}

bool
sys_remove (const char *file) {
	return syscall1 (SYS_REMOVE, file);
}

int
sys_open (const char *file) {
	return syscall1 (SYS_OPEN, file);
}

int
sys_filesize (int fd) {
	return syscall1 (SYS_FILESIZE, fd);
}

int
sys_read (int fd, void *buffer, unsigned size) {
	return syscall3 (SYS_READ, fd, buffer, size);
}

int
sys_write (int fd, const void *buffer, unsigned size) {
	return syscall3 (SYS_WRITE, fd, buffer, size);
}

void
sys_seek (int fd, unsigned position) {
	syscall2 (SYS_SEEK, fd, position);
}

unsigned
sys_tell (int fd) {
	return syscall1 (SYS_TELL, fd);
}

void
sys_close (int fd) {
	syscall1 (SYS_CLOSE, fd);
}