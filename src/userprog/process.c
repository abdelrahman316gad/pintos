#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/syscall.h"
static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);
struct thread* child_id(tid_t tid);
#define MAX_ARGS_SIZE 4096
/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *file_name)
{
    char *fn_copy;
    tid_t tid;
    /* Make a copy of FILE_NAME.
    Otherwise there's a race between the caller and load(). */
     char *fn_copy_2;
     char *save_ptr;  
    fn_copy = palloc_get_page(0);
    if (fn_copy == NULL)
    return TID_ERROR;
    strlcpy(fn_copy, file_name, PGSIZE);
    fn_copy_2 = malloc ( strlen(file_name) + 1);
    if (fn_copy_2 == NULL)
    {
      palloc_free_page (fn_copy);
      return TID_ERROR;
    }
    strlcpy (fn_copy_2, file_name, PGSIZE);
  file_name = strtok_r (fn_copy_2, " ", &save_ptr);
    tid = thread_create (file_name, PRI_DEFAULT, start_process, fn_copy);
    free (fn_copy_2);
    sema_down(&thread_current()->sema_wait_parent);
    if(tid == TID_ERROR)
        palloc_free_page(fn_copy);

    if (thread_current()->child_creation_success)
    {
        return tid;
    }  
    return TID_ERROR;
}
static void 
set_up_stack(struct thread * Parent)
{
     struct list* Children = &Parent->children;
      struct thread* Child = thread_current();
      list_push_back(Children,&Child->child_elem); 
       Parent->child_creation_success = 1;
}
/*
 * Return child with given tid
 * */
struct thread* child_id(tid_t tid){
  struct list* Children = &thread_current()->children;
  struct list_elem *e;
  for (e = list_begin (Children); e != list_end (Children); e = list_next (e))
    {
      struct thread *t = list_entry (e, struct thread, child_elem);
      if (t->tid == tid)
        return t;
    }
    return NULL;
}
/* A thread function that loads a user process and starts it
   running. */
static void
start_process (void *file_name_)
{
  char *file_name = file_name_;
  struct intr_frame if_;
  bool success;
  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  success = load (file_name, &if_.eip, &if_.esp);
  struct thread* Parent = thread_current()->parent;
  if(success){ 
      set_up_stack(Parent);
      sema_up(&Parent->sema_wait_parent); 
      sema_down(&thread_current()->sema_wait_parent); 
  }else{     
        Parent->child_creation_success = 0; 
        sema_up(&Parent->sema_wait_parent); 
    }
    palloc_free_page (file_name);
  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}
 
/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.
 
   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int
process_wait (tid_t tid )
{
    struct thread * cur = thread_current(); 
    cur-> waiting_for = tid;
    struct thread* Child = child_id(tid);
    int status=-1;
    if(Child != NULL){ 
        list_remove(&Child->child_elem); 
        sema_up(&Child->sema_wait_parent); 
       sema_down(&cur->sema_wait_child); 
      status = cur->child_status;
    }
    return status; 
}
/* Free the current process's resources. */
void
process_exit (void) {
    if (thread_current()->parent != NULL ) {
        struct thread *parent = thread_current()->parent;
        if (parent->waiting_for == thread_current()->tid) {  
            parent->child_status = thread_current()->exit_status; 
            parent->waiting_for = -1; 
            parent->child_creation_success = 0; 
            sema_up(&parent->sema_wait_child); 
        }
    }
    struct list* Children = &thread_current()->children;
  struct list_elem *e2;
  for (e2 = list_begin (Children); e2!= list_end (Children); e2 = list_next (e2))
    {
      struct thread *t = list_entry (e2, struct thread, child_elem);
      t->parent = NULL;
      sema_up(&t->sema_wait_parent);
      list_remove(&t->child_elem);
    }

    file_close(thread_current()->executing);
    thread_current()->executing = NULL;
    thread_current()->parent = NULL;
    struct list* process_files = &thread_current()->user_files;
    for(struct list_elem* iter = list_begin(process_files);
        iter !=list_end(process_files) ; ){
        struct user_file* file = list_entry(iter, struct user_file , elem);
        iter=list_next(iter);
        file_close(file->file);
        list_remove(&file->elem);
        free(file);
    }
  
    uint32_t *pd;
    /* Destroy the current process's page directory and switch back
       to the kernel-only page directory. */
    pd = thread_current()->pagedir;
    if (pd != NULL){
        /* Correct ordering here is crucial.  We must set
           cur->pagedir to NULL before switching page directories,
           so that a timer interrupt can't switch back to the
           process page directory.  We must activate the base page
           directory before destroying the process's page
           directory, or our active page directory will be one
           that's been freed (and cleared). */
        thread_current()->pagedir = NULL;
        pagedir_activate(NULL);
        pagedir_destroy(pd);
    }
}
/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();
 
  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);
 
  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}
 
 

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */
 
/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;
 
/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */
 
/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };
 
/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };
 
/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */
 
/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */
 
static bool setup_stack (void **esp);
void stack_args(void** esp , char* filename_with_args);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);


/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *file_name, void (**eip) (void), void **esp) 
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;
 
  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  char *fn_copy_2;
  char *save_ptr;
  //int name_length = strlen (file_name)+1;
  //fn_copy = malloc (name_length);
  //strlcpy(fn_copy, file_name, name_length);
  //fn_copy = strtok_r (fn_copy, " ", &save_ptr); 

  fn_copy_2 = malloc ( strlen(file_name) + 1);
    if (fn_copy_2 == NULL)
    {
      palloc_free_page (fn_copy_2);
      return TID_ERROR;
    }
    strlcpy (fn_copy_2, file_name, PGSIZE);
  fn_copy_2 = strtok_r (fn_copy_2, " ", &save_ptr);
  if (t->pagedir == NULL) 
    goto done;
  process_activate ();


  file = filesys_open (fn_copy_2);
  if (file == NULL) 
    {
      printf ("load: %s: open failed\n", file_name);
      goto done; 
    }
 
  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024) 
    {
      printf ("load: %s: error loading executable\n", fn_copy_2);
      goto done;
    }

    /* Pointer to executable file */
    thread_current()->executing = file;

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) 
    {
      struct Elf32_Phdr phdr;
 
      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);
 
      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofs += sizeof phdr;
      switch (phdr.p_type) 
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, file)) 
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else 
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              if (!load_segment (file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable))
                goto done;
            }
          else
            goto done;
          break;
        }
    }
 
  /* Set up stack. */
  if (!setup_stack (esp))
    goto done;

   /* Push stack args */
    set_stack(fn_copy_2, esp, &save_ptr);
    free(fn_copy_2); // free file name copy
 
  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;
 
  success = true;
 
 done:
  /* We arrive here whether the load is successful or not. */

   if(success) // Loaded successfully
       file_deny_write(file);

  return success;
}

/* load() helpers. */
 
static bool install_page (void *upage, void *kpage, bool writable);
 
/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file) 
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) 
    return false; 
 
  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file)) 
    return false;
 
  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz) 
    return false; 
 
  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;
  
  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;
 
  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;
 
  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;
 
  /* It's okay. */
  return true;
}
 
/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:
 
        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.
 
        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.
 
   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.
 
   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable) 
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);
 
  file_seek (file, ofs);
  while (read_bytes > 0 || zero_bytes > 0) 
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;
 
      /* Get a page of memory. */
      uint8_t *kpage = palloc_get_page (PAL_USER);
      if (kpage == NULL)
        return false;
 
      /* Load this page. */
      if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes)
        {
          palloc_free_page (kpage);
          return false; 
        }
      memset (kpage + page_read_bytes, 0, page_zero_bytes);
 
      /* Add the page to the process's address space. */
      if (!install_page (upage, kpage, writable)) 
        {
          palloc_free_page (kpage);
          return false; 
        }
 
      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
    }
  return true;
}
 
/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp)
{
  uint8_t *kpage;
  bool success = false;
  kpage = palloc_get_page (PAL_USER | PAL_ZERO);
  if (kpage != NULL) 
    {
      success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true);
      if (success) {
          *esp = PHYS_BASE;
      }else
        palloc_free_page (kpage);
    }
  return success;
}
 


void set_stack(char* token, void **esp, char **save_ptr){

int args_pushed;
  int argc = 0;
  void* stack_pointer;

  stack_pointer = *esp;

  /* Tokenise file name and push each token on the stack. */
  do                                                                            
     {                                                                           
       size_t len = strlen (token) + 1;                                          
       stack_pointer = (void*) (((char*) stack_pointer) - len);                  
       strlcpy ((char*)stack_pointer, token, len);                               
       argc++;                                   
       /* Don't push anymore arguments if maximum allowed 
          have already been pushed. */
       if (PHYS_BASE - stack_pointer > MAX_ARGS_SIZE)
          return 0;                              
       token = strtok_r (NULL, " ", save_ptr);                                  
     } while (token != NULL);
  
  char *arg_ptr = (char*) stack_pointer;                                      
  
  /* Round stack pionter down to a multiple of 4. */
  stack_pointer = (void*) (((intptr_t) stack_pointer) & 0xfffffffc);

  /* Push null sentinel. */
  stack_pointer = (((char**) stack_pointer) - 1);
  *((char*)(stack_pointer)) = 0;

  /* Push pointers to arguments. */
  args_pushed = 0;                                                              
  while (args_pushed < argc)                                                    
     {                                                                           
       while (*(arg_ptr - 1) != '\0')                                            
         ++arg_ptr;                                                              
       stack_pointer = (((char**) stack_pointer) - 1);                           
       *((char**) stack_pointer) = arg_ptr;                                      
       ++args_pushed;    
       ++arg_ptr;                                                        
     }

  /* Push argv. */
  char** first_arg_pointer = (char**) stack_pointer;
  stack_pointer = (((char**) stack_pointer) - 1);
  *((char***) stack_pointer) = first_arg_pointer;


  /* Push argc. */
  int* stack_int_pointer = (int*) stack_pointer;
  --stack_int_pointer;
  *stack_int_pointer = argc;
  stack_pointer = (void*) stack_int_pointer;

  /* Push null sentinel. */
  stack_pointer = (((void**) stack_pointer) - 1);
  *((void**)(stack_pointer)) = 0;

  *esp = stack_pointer;
  return 1;
}


/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();
 
  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}