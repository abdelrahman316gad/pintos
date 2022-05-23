#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "process.h"


static void syscall_handler (struct intr_frame *);

static void sys_halt();
void sys_exit(int status);
static tid_t sys_exec(const char *file);
static int sys_wait (tid_t tid);


static struct lock lock;
typedef int tid_t;

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
    lock_init (&lock);

}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  //check validation
  int *stackPointer = f->esp;
  if ( !is_user_vaddr(stackPointer) || !is_user_vaddr(stackPointer+1) || !is_user_vaddr(stackPointer+2) || !is_user_vaddr(stackPointer+3))
    sys_exit(-1);
  //the max call will need 3 adresses

  if(*stackPointer < SYS_HALT || *stackPointer > SYS_INUMBER){
    sys_exit(-1);
  }

  // here param_esp = f->esp;  in read write calls

  // stack pointer habal
  int result = 0;
  switch (*stackPointer){
    case SYS_HALT:
      sys_halt() ;

      break;
    case SYS_EXIT:
      sys_exit(*(stackPointer+1)) ;

      break;
    case SYS_EXEC:
      result = sys_exec(*(stackPointer+1)) ;

      break;
    case SYS_WAIT:
      result = sys_wait(*(stackPointer+1)) ;

      break;
    case SYS_CREATE:

      break;
    case SYS_REMOVE:

      break;
    case SYS_OPEN:

      break;
    case SYS_FILESIZE:

      break;
    case SYS_READ:

      break;
    case SYS_WRITE:

      break;
    case SYS_SEEK:

      break;
    case SYS_TELL:

      break;
    case SYS_CLOSE:

      break;
    case SYS_MMAP:

      break;
    case SYS_MUNMAP: 

      break;
    default:
      sys_exit(-1) ;

  }


  printf ("system call!\n");
  thread_exit ();
}


static void sys_halt()
{
  shutdown_power_off ();
}


void sys_exit (int status)
{
  struct thread *t = thread_current();
  struct list_elem *e;

  //release all held resorces
  if (lock_held_by_current_thread(&lock))
    lock_release (&lock);

  /* Close all opened files of the thread. */
  /* Unmap all memory mapped files of the thread. */

  //t->ret_status = status;
  
  thread_exit();
}


static tid_t sys_exec (const char *file)
{
  lock_acquire(&lock);
  tid_t ret = process_execute(file);
  lock_release(&lock);
  return ret;
}


static int sys_wait (tid_t tid)
{
  return process_wait(tid);
}







