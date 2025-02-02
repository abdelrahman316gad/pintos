/* This file is derived from source code for the Nachos
   instructional operating system.  The Nachos copyright notice
   is reproduced in full below. */

/* Copyright (c) 1992-1996 The Regents of the University of California.
   All rights reserved.

   Permission to use, copy, modify, and distribute this software
   and its documentation for any purpose, without fee, and
   without written agreement is hereby granted, provided that the
   above copyright notice and the following two paragraphs appear
   in all copies of this software.

   IN NO EVENT SHALL THE UNIVERSITY OF CALIFORNIA BE LIABLE TO
   ANY PARTY FOR DIRECT, INDIRECT, SPECIAL, INCIDENTAL, OR
   CONSEQUENTIAL DAMAGES ARISING OUT OF THE USE OF THIS SOFTWARE
   AND ITS DOCUMENTATION, EVEN IF THE UNIVERSITY OF CALIFORNIA
   HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

   THE UNIVERSITY OF CALIFORNIA SPECIFICALLY DISCLAIMS ANY
   WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
   WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
   PURPOSE.  THE SOFTWARE PROVIDED HEREUNDER IS ON AN "AS IS"
   BASIS, AND THE UNIVERSITY OF CALIFORNIA HAS NO OBLIGATION TO
   PROVIDE MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS, OR
   MODIFICATIONS.
*/

#include "threads/synch.h"
#include <stdio.h>
#include <string.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

/* Initializes semaphore SEMA to VALUE.  A semaphore is a
   nonnegative integer along with two atomic operators for
   manipulating it:

   - down or "P": wait for the value to become positive, then
     decrement it.

   - up or "V": increment the value (and wake up one waiting
     thread, if any). */
void
sema_init (struct semaphore *sema, unsigned value)
{
    ASSERT (sema != NULL);

    sema->value = value;
    list_init (&sema->waiters);
}

/* Down or "P" operation on a semaphore.  Waits for SEMA's value
   to become positive and then atomically decrements it.

   This function may sleep, so it must not be called within an
   interrupt handler.  This function may be called with
   interrupts disabled, but if it sleeps then the next scheduled
   thread will probably turn interrupts back on. */
void
sema_down (struct semaphore *sema)
{
    enum intr_level old_level;

    ASSERT (sema != NULL);
    ASSERT (!intr_context ());

    old_level = intr_disable ();
    while (sema->value == 0)
    {
        // we insert the thread in their priority order.
              list_push_back (&sema->waiters, &thread_current ()->elem);
        // list_insert_ordered (&sema->waiters, &thread_current()->elem,&compare_priority,NULL);
        thread_block ();
    }
    sema->value--;
    intr_set_level (old_level);
}

/* Down or "P" operation on a semaphore, but only if the
   semaphore is not already 0.  Returns true if the semaphore is
   decremented, false otherwise.

   This function may be called from an interrupt handler. */
bool
sema_try_down (struct semaphore *sema)
{
    enum intr_level old_level;
    bool success;

    ASSERT (sema != NULL);

    old_level = intr_disable ();
    if (sema->value > 0)
    {
        sema->value--;
        success = true;
    }
    else
        success = false;
    intr_set_level (old_level);

    return success;
}

/* Up or "V" operation on a semaphore.  Increments SEMA's value
   and wakes up one thread of those waiting for SEMA, if any.

   This function may be called from an interrupt handler. */
void
sema_up (struct semaphore *sema)
{
    enum intr_level old_level;

    ASSERT (sema != NULL);

    old_level = intr_disable ();
    if (!list_empty (&sema->waiters)) {
        list_sort(&sema->waiters, &compare_priority, NULL);
        thread_unblock(list_entry(list_pop_front(&sema->waiters),struct thread, elem));
    }
    sema->value++;
    // thread_yield();
    intr_set_level (old_level);
}

static void sema_test_helper (void *sema_);

/* Self-test for semaphores that makes control "ping-pong"
   between a pair of threads.  Insert calls to printf() to see
   what's going on. */
void
sema_self_test (void)
{
    struct semaphore sema[2];
    int i;

    printf ("Testing semaphores...");
    sema_init (&sema[0], 0);
    sema_init (&sema[1], 0);
    thread_create ("sema-test", PRI_DEFAULT, sema_test_helper, &sema);
    for (i = 0; i < 10; i++)
    {
        sema_up (&sema[0]);
        sema_down (&sema[1]);
    }
    printf ("done.\n");
}

/* Thread function used by sema_self_test(). */
static void
sema_test_helper (void *sema_)
{
    struct semaphore *sema = sema_;
    int i;

    for (i = 0; i < 10; i++)
    {
        sema_down (&sema[0]);
        sema_up (&sema[1]);
    }
}

/* Initializes LOCK.  A lock can be held by at most a single
   thread at any given time.  Our locks are not "recursive", that
   is, it is an error for the thread currently holding a lock to
   try to acquire that lock.

   A lock is a specialization of a semaphore with an initial
   value of 1.  The difference between a lock and such a
   semaphore is twofold.  First, a semaphore can have a value
   greater than 1, but a lock can only be owned by a single
   thread at a time.  Second, a semaphore does not have an owner,
   meaning that one thread can "down" the semaphore and then
   another one "up" it, but with a lock the same thread must both
   acquire and release it.  When these restrictions prove
   onerous, it's a good sign that a semaphore should be used,
   instead of a lock. */
void
lock_init (struct lock *lock)
{
    ASSERT (lock != NULL);

    lock->holder = NULL;
    sema_init (&lock->semaphore, 1);
}

/* Acquires LOCK, sleeping until it becomes available if
   necessary.  The lock must not already be held by the current
   thread.

   This function may sleep, so it must not be called within an
   interrupt handler.  This function may be called with
   interrupts disabled, but interrupts will be turned back on if
   we need to sleep. */
void
lock_acquire (struct lock *lock)
{
    ASSERT (lock != NULL);
    ASSERT (!intr_context ());
    ASSERT (!lock_held_by_current_thread (lock));
    enum intr_level  old_level = intr_disable ();
    struct thread *lock_holder = lock->holder;
    struct thread *cur = thread_current();
    if(!thread_mlfqs){
        if(lock_holder != NULL)
        {
            if(cur->priority > lock_holder->priority)
            {
                //if it is higher we donate it the priority
                lock_holder->priority = cur->priority;
                cur->thread_waiting_for = lock_holder;
                 //Then we put it in the list waiting for this thread
                list_insert_ordered(&(lock->holder->threads_waiting), &cur->wait_elem, &compare_priority,NULL);
                //Finally we donate the priority of the current thread for the threads chain that the lock holder is waiting for by looping through them and checking
                //if their priority is smaller
                 int holder_priority = lock_holder->priority;
            lock_holder = lock_holder->thread_waiting_for;
            while (lock_holder != NULL)
            {
                if(lock_holder->priority < holder_priority)
                    lock_holder->priority = holder_priority;
                holder_priority = lock_holder->priority;
                lock_holder = lock_holder->thread_waiting_for;
            }
        }
    }
}
    //We put the current thread in sema waiters
    sema_down (&lock->semaphore);
     //We set the current thread as lock holder
    lock->holder = thread_current();
    intr_set_level(old_level);

}

/* Tries to acquires LOCK and returns true if successful or false
   on failure.  The lock must not already be held by the current
   thread.

   This function will not sleep, so it may be called within an
   interrupt handler. */
bool
lock_try_acquire (struct lock *lock)
{
    bool success;

    ASSERT (lock != NULL);
    ASSERT (!lock_held_by_current_thread (lock));

    success = sema_try_down (&lock->semaphore);
    if (success)
        lock->holder = thread_current ();
    return success;
}

/* Releases LOCK, which must be owned by the current thread.

   An interrupt handler cannot acquire a lock, so it does not
   make sense to try to release a lock within an interrupt
   handler. */
void
lock_release (struct lock *lock)
{
    // ASSERT (lock != NULL);
    // ASSERT (lock_held_by_current_thread (lock));
    // struct thread *cur= thread_current();
    // struct thread* helping_thread;
    // struct semaphore *sema = &lock->semaphore;
    // if(!thread_mlfqs){
    //     //we see if sema waiters is not empty
    //     if (!list_empty (&sema->waiters))
    //     {
    //         //we pick the highest priority waiting thread to unblock it and acquire it in the lock after realsing the previous realase it 
    //         list_sort(&sema->waiters,&compare_priority,NULL);
    //         helping_thread = list_entry (list_pop_front (&sema->waiters),struct thread, elem);
    //         thread_unblock (helping_thread);
    //         //we set the thread it is waiting for as it now it will acquire the lock .
    //         helping_thread->thread_waiting_for = NULL;
    //         // we remove the higher priority thread from the thread that relase the lock .
    //         if(!list_empty(&cur->threads_waiting))
    //         {
    //             list_remove(&helping_thread->wait_elem);
    //         }
    //         // we remove the threads waiting in the semaphore list from the threads wwaiting list that realse the lock and add it to higher priority that now acquire the lock .
    //         for(struct list_elem *e = list_begin(&sema->waiters); e != list_end(&sema->waiters); e= list_next(e))
    //         {
    //             struct thread *temp = list_entry(e, struct thread, elem);
    //             list_remove(&temp->wait_elem);
    //             temp->thread_waiting_for = helping_thread;
    //             list_insert_ordered(&helping_thread->threads_waiting, &temp->wait_elem, &compare_priority, NULL);
    //         }
    //     }
    //     /// we set the priority of the thread that will acquire the lock to the thread that has the highest priority to its newest thread waiting list if it has a prioiruty larger than its actual priority . 
    //     if(!list_empty(&cur->threads_waiting))
    //     {
    //         cur->priority = cur->actual_priority;
    //         struct thread *temp =list_entry(list_front(&cur->threads_waiting), struct thread, wait_elem);
    //         if(&cur->priority < &temp->priority)
    //         {
    //             cur-> priority = temp->priority;
    //         }
    //         else
    //         {
    //             cur->priority = cur->actual_priority;
    //         }
    //     }
    //     else
    //     {
    //         cur->priority = cur->actual_priority;
    //     }
    // }
    // enum intr_level old_level = intr_disable ();
    // lock->holder = NULL;
    // sema_up(&lock->semaphore);
    //   intr_set_level (old_level);
  ASSERT (lock != NULL);
  ASSERT (lock_held_by_current_thread (lock));

  lock->holder = NULL;
  sema_up (&lock->semaphore);
}

/* Returns true if the current thread holds LOCK, false
   otherwise.  (Note that testing whether some other thread holds
   a lock would be racy.) */
bool
lock_held_by_current_thread (const struct lock *lock)
{
    ASSERT (lock != NULL);

    return lock->holder == thread_current ();
}

/* One semaphore in a list. */
struct semaphore_elem
{
    struct list_elem elem;              /* List element. */
    struct semaphore semaphore;         /* This semaphore. */
    struct thread *t;
};

/* Initializes condition variable COND.  A condition variable
   allows one piece of code to signal a condition and cooperating
   code to receive the signal and act upon it. */
void
cond_init (struct condition *cond)
{
    ASSERT (cond != NULL);

    list_init (&cond->waiters);
}

bool
compare_sema (const struct list_elem *a, const struct list_elem *b, void *aux UNUSED)
{
    return (list_entry (a,struct semaphore_elem, elem)->t->priority > list_entry (b,struct semaphore_elem, elem)->t->priority);
}
/* Atomically releases LOCK and waits for COND to be signaled by
   some other piece of code.  After COND is signaled, LOCK is
   reacquired before returning.  LOCK must be held before calling
   this function.

   The monitor implemented by this function is "Mesa" style, not
   "Hoare" style, that is, sending and receiving a signal are not
   an atomic operation.  Thus, typically the caller must recheck
   the condition after the wait completes and, if necessary, wait
   again.

   A given condition variable is associated with only a single
   lock, but one lock may be associated with any number of
   condition variables.  That is, there is a one-to-many mapping
   from locks to condition variables.

   This function may sleep, so it must not be called within an
   interrupt handler.  This function may be called with
   interrupts disabled, but interrupts will be turned back on if
   we need to sleep. */

void
cond_wait (struct condition *cond, struct lock *lock)
{
    struct semaphore_elem  waiter;
    ASSERT (cond != NULL);
    ASSERT (lock != NULL);
    ASSERT (!intr_context ());
    ASSERT (lock_held_by_current_thread (lock));
    waiter.t = thread_current();
    sema_init (&waiter.semaphore, 0);
    // we insert the semaphores in order according to their thread priority.
    list_insert_ordered (&cond->waiters, &waiter.elem, &compare_sema ,NULL);
    lock_release (lock);
    sema_down (&waiter.semaphore);
    lock_acquire (lock);
}

/* If any threads are waiting on COND (protected by LOCK), then
   this function signals one of them to wake up from its wait.
   LOCK must be held before calling this function.

   An interrupt handler cannot acquire a lock, so it does not
   make sense to try to signal a condition variable within an
   interrupt handler. */
void
cond_signal (struct condition *cond, struct lock *lock UNUSED)
{
    ASSERT (cond != NULL);
    ASSERT (lock != NULL);
    ASSERT (!intr_context ());
    ASSERT (lock_held_by_current_thread (lock));
    // we get the sema that has the thread of the higher priority .
    if (!list_empty (&cond->waiters))
        sema_up (&list_entry (list_pop_front (&cond->waiters),
    struct semaphore_elem, elem)->semaphore);
}

/* Wakes up all threads, if any, waiting on COND (protected by
   LOCK).  LOCK must be held before calling this function.

   An interrupt handler cannot acquire a lock, so it does not
   make sense to try to signal a condition variable within an
   interrupt handler. */
void
cond_broadcast (struct condition *cond, struct lock *lock)
{
    ASSERT (cond != NULL);
    ASSERT (lock != NULL);

    while (!list_empty (&cond->waiters))
        cond_signal (cond, lock);
}
