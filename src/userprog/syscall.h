#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "threads/thread.h"
#include "threads/interrupt.h"
#include "stdbool.h"

void tell(struct intr_frame *f);
void syscall_init (void);
bool valid_esp(struct intr_frame *f);
int close(int fd);
static void syscall_handler (struct intr_frame *f);
void seek(struct intr_frame *f);
tid_t wait(tid_t tid);
int create(char * file_name,int initial_size);
struct user_file *  get_file( int  fd);
int read(int fd,char* bbuffer,unsigned size);
int write(int fd,char * buffer,unsigned size);
void halt();
void exit(int status);
bool valid (void * name);
struct lock lock;
int remove(char * name);
int open(char * file_name);
void get_size(struct intr_frame *f);

#endif /* userprog/syscall.h */
