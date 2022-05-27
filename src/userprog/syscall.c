#include "userprog/syscall.h"
#include "devices/shutdown.h" // for SYS_HALT
#include "threads/thread.h"
#include "threads/init.h"
#include "threads/vaddr.h"
#include "lib/kernel/list.h"
#include <stdio.h>
#include "threads/synch.h"
#include "filesys/filesys.h"
#include <syscall-nr.h>
#include "filesys/file.h"
#include "threads/interrupt.h"

void
syscall_init (void)
{
    intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
    lock_init(&lock);
}

int remove(char * name){
    int result = -1;
    lock_acquire(&lock);
    result = filesys_remove(name);
    lock_release(&lock);
    return result;
}

void wrapper_remove(struct intr_frame *f){
    if(!valid((char *) (*((int *) f->esp + 1)))){
        exit(-1);
    }
    f->eax = remove((char *) (*((int *) f->esp + 1)));
}

void tell(struct intr_frame *f){
    struct user_file * file = get_file((int ) (*((int *) f->esp + 1)));
    if(file !=  NULL){
        lock_acquire(&lock);
        f->eax = file_tell(file->file);
        lock_release(&lock);

    }else{
        f->eax =- 1;
    }
}

void seek(struct intr_frame *f){
    unsigned pos = (unsigned) (*((int *) f->esp + 2));
    struct user_file * file = get_file((int ) (*((int *) f->esp + 1)));
    if(file ==  NULL){
        f->eax =- 1;
    }else{
        lock_acquire(&lock);
        file_seek(file->file,pos);
        f->eax = pos;
        lock_release(&lock);
    }
}

static void
syscall_handler (struct intr_frame *f) {
    if(!valid_esp(f)) exit(-1);
    switch(*(int*)f->esp) {
        case SYS_WAIT:
        {
            wrapper_wait(f);
            break;
        }
        case SYS_EXEC:
        {
            wrapper_exec(f);
            break;
        }
        case SYS_HALT:
        {
            halt();
            break;
        }
        case SYS_WRITE:
        {
            wrapper_write(f);
            break;
        }
        case SYS_CREATE:
        {
            wrapper_create(f);
            break;
        }
        case SYS_EXIT:
        {
            wrapper_exit(f);
            break;
        }
        case SYS_CLOSE:
        {
            wrapper_close(f);
            break;
        }
        case SYS_OPEN :
        {
            wrapper_open(f);
            break;
        }
        case SYS_FILESIZE:
        {
            get_size(f);
            break;
        }
        case SYS_READ :
        {
            wrapper_read(f);
            break;
        }
        case SYS_SEEK:
        {
            seek(f);
            break;
        }
        case SYS_REMOVE:
        {
            wrapper_remove(f);
            break;
        }
        case SYS_TELL:
        {
            tell(f);
            break;
        }
        default:{}
    }

}


void get_size(struct intr_frame *f){
    struct user_file * x = get_file((int ) (*((int *) f->esp + 1)));
    if(x !=  NULL){
        lock_acquire(&lock);
        f->eax = file_length(x->file);
        lock_release(&lock);
    }else{
        f->eax =- 1;
    }
}

void wrapper_read(struct intr_frame *f){
    if((int ) (*((int *) f->esp + 1))==1 || !valid((char * ) (*((int *) f->esp + 2)))){
        // fd is 1 means (stdout ) so it is not allowed
        exit(-1);
    }
    unsigned size = *((unsigned *) f->esp + 3);
    f->eax = read((int ) (*((int *) f->esp + 1)),(char * ) (*((int *) f->esp + 2)),size);
}

int read(int fd,char* buffer,unsigned size){
    int x = size;
    if(fd ==1){}
    else if(fd ==0){
        while (size)
        {
            lock_acquire(&lock);
            char c = input_getc();
            lock_release(&lock);
            buffer+=c;
            size-=1;
        }
        return x;
    }

    struct user_file * temp =get_file(fd);

    if(temp!=NULL){
        struct file * file = temp->file;
        lock_acquire(&lock);
        size = file_read(file,buffer,size);
        lock_release(&lock);
        return size;
    }else return -1;
}

void wrapper_close(struct intr_frame *f){
    if((int) (*((int *) f->esp + 1))<2) exit(-1);
    f->eax = close((int) (*((int *) f->esp + 1)));
}

void wrapper_open(struct intr_frame *f){
    if(!valid((char *) (*((int *) f->esp + 1)))) exit(-1);
    f->eax = open((char *) (*((int *) f->esp + 1)));
}

void wrapper_create(struct intr_frame *f){
    if(!valid((char * )*((int  *)f->esp + 1 ))) exit(-1);
    f->eax = create((char * )*((int  *)f->esp + 1 ),(unsigned) *((int *) f->esp + 2 ));
}

void wrapper_write(struct intr_frame *f){
    if(!valid((char *) (*((int *) f->esp + 2))) || *((int *) f->esp + 1) ==0) exit(-1);
    f->eax = write(*((int *) f->esp + 1), (char *) (*((int *) f->esp + 2)), (unsigned)(*((int*) f->esp + 3)));
}

void wrapper_wait(struct intr_frame *f){
    if(!valid((int*)f->esp + 1))exit(-1);
    f->eax = wait(*((int*)f->esp + 1));
}

void wrapper_exit(struct intr_frame *f){
    if(!is_user_vaddr(*((int*)f->esp + 1))) {
        f->eax = -1;
        exit(-1);
    }
    f->eax = *((int*)f->esp + 1);
    exit(*((int*)f->esp + 1));
}

void wrapper_exec(struct intr_frame *f){
    char *file_name = (char *) (*((int *) f->esp + 1));
    f->eax = process_execute(file_name);
}

int close(int fd){
    struct user_file  *file = get_file(fd);
    if(file==NULL) return -1;
    lock_acquire(&lock);
    file_close(file->file);
    lock_release(&lock);
    list_remove(&file->elem);
    return 1;
}

int  create(char * file_name,int initial_size){
    int result = 0;
    lock_acquire(&lock);
    result = filesys_create (file_name,initial_size);
    lock_release(&lock);
    return result;
}

int write(int fd,char * buffer,unsigned size){
    if(fd ==0){}
    else if (fd == 1) {
        lock_acquire(&lock);
        putbuf(buffer, size);
        lock_release(&lock);
        return size;
    }
    struct user_file *xfile = get_file(fd);
    if(xfile !=NULL){
        int result = 0;
        lock_acquire(&lock);
        result = file_write(xfile->file,buffer,size);
        lock_release(&lock);
        return result;
    }else return -1;
}

int open(char * file_name){
    static unsigned long curent = 2;
    lock_acquire(&lock);
    struct file * opened_file  = filesys_open(file_name);
    lock_release(&lock);
    if(opened_file==NULL) return -1;
    else{
        struct user_file* xfile = (struct user_file*) malloc(sizeof(struct user_file));
        xfile->file = opened_file;
        xfile->fd = curent;
        int file_fd = curent;
        lock_acquire(&lock);
        curent++;
        lock_release(&lock);
        list_push_back(&thread_current()->user_files, &xfile->elem);
        return file_fd;
    }
}

void halt(){
    printf("(halt) begin\n");
    shutdown_power_off();
}

bool valid_esp(struct intr_frame *f ){
    return valid((int*)f->esp) || ((*(int*)f->esp) < 0) || (*(int*)f->esp) > 12;
}

tid_t wait(tid_t tid){
    return process_wait(tid);
}

bool valid ( void * name){
    return name!=NULL && is_user_vaddr(name) && pagedir_get_page(thread_current()->pagedir, name) != NULL;
}

struct user_file *  get_file( int  fd){
    // struct user_file* ans = NULL;
    struct list *l  = &(thread_current()->user_files);
    for(struct list_elem* e = list_begin(l); e!=list_end(l) ; e =list_next(e)){
        if((list_entry(e, struct user_file , elem)->fd) ==fd) return list_entry(e, struct user_file , elem);
        //lw feh errors momkn tib2a hina
    }
    return NULL;
}

void exit(int status){
    char * save_ptr;
    char * executable = strtok_r (thread_current()->name, " ", &save_ptr);
    thread_current()->exit_status = status;
    printf("%s: exit(%d)\n",executable,status);
    thread_exit();
}