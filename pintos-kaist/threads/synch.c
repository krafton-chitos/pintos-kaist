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


static void donate_priority (struct thread *);
// static bool donator_already_in_list(struct list *, struct thread *);
static void remove_donations_for_lock(struct lock *lock);

/* Initializes semaphore SEMA to VALUE.  A semaphore is a
   nonnegative integer along with two atomic operators for
   manipulating it:

   - down or "P": wait for the value to become positive, then
   decrement it.

   - up or "V": increment the value (and wake up one waiting
   thread, if any). */
void
sema_init (struct semaphore *sema, unsigned value) {
	ASSERT (sema != NULL);

	sema->value = value;
	list_init (&sema->waiters);
}

/* Down or "P" operation on a semaphore.  Waits for SEMA's value
   to become positive and then atomically decrements it.

   This function may sleep, so it must not be called within an
   interrupt handler.  This function may be called with
   interrupts disabled, but if it sleeps then the next scheduled
   thread will probably turn interrupts back on. This is
   sema_down function. */
void
sema_down (struct semaphore *sema) {
	enum intr_level old_level;
	ASSERT (sema != NULL);
	ASSERT (!intr_context ());

	old_level = intr_disable ();

   // 세마포어 자원이 0이면 waiters 리스트에 현재 스레드를 priority 순으로 삽입
	while (sema->value == 0) {
		list_insert_ordered (&sema->waiters, &thread_current()->elem, cmp_priority, NULL);
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
sema_try_down (struct semaphore *sema) {
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
sema_up (struct semaphore *sema) {
	enum intr_level old_level;
	struct thread *unblocked = NULL;

	ASSERT (sema != NULL);
	
	old_level = intr_disable ();

	if (!list_empty (&sema->waiters)){
		list_sort(&sema->waiters, cmp_priority, NULL);
		unblocked = list_entry(list_pop_front(&sema->waiters), struct thread, elem);
		thread_unblock(unblocked);
	}

	sema->value++;

	intr_set_level (old_level);
	
	if ((unblocked != NULL) && (unblocked->priority > thread_current() -> priority))
		thread_yield();

}

static void sema_test_helper (void *sema_);

/* Self-test for semaphores that makes control "ping-pong"
   between a pair of threads.  Insert calls to printf() to see
   what's going on. */
void
sema_self_test (void) {
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
sema_test_helper (void *sema_) {
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
lock_init (struct lock *lock) {
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
lock_acquire (struct lock *lock) {
	ASSERT (lock != NULL);
	ASSERT (!intr_context ());
	ASSERT (!lock_held_by_current_thread (lock));
	// 일단 후원을 하고, 풀리는 지 확인해봄. (락을 풀어 주기를 유도한다고 했으니까...)
	// 후원하고 안풀리면 유감. 이런느낌 ? -> 일단 시도. 
	// 여기서 일단 lock held를 가지고 있는 애 보다 우선 순위가 커야함
	struct thread *curr = thread_current();

	if(lock->holder != NULL){
		curr->wait_on_lock = lock;
		donate_priority(curr);
      thread_re_sort();
	}

	if (lock->holder != NULL && !thread_mlfqs) {
    struct thread *cur = thread_current();
    cur->wait_on_lock = lock;

    list_insert_ordered(&lock->holder->donation, &cur->d_elem, thread_donation_cmp, NULL);

    donate_priority();
}
	sema_down (&lock->semaphore);
	lock->holder = thread_current ();
	curr->wait_on_lock = NULL;

}

static void
donate_priority (struct thread *donator) {
	struct lock *target_lock = donator->wait_on_lock;

   if (donator->priority > target_lock->holder->priority) {
      list_push_back(&target_lock->holder->donations, &donator->d_elem);
   }

	while (target_lock != NULL) {
		struct thread *target_holder = target_lock->holder;

		if (donator->priority > target_holder->priority) {
			target_holder->priority = donator->priority;
      }
      
		target_lock = target_holder->wait_on_lock;
	}
}

// static bool 
// donator_already_in_list(struct list *donations, struct thread *donator) {
//     struct list_elem *e;

// 	if (list_empty(donations)) return false;

//     for (e = list_begin(donations); e != list_end(donations); e = list_next(e)) {
//         struct thread *t = list_entry(e, struct thread, d_elem);
//         if (t == donator) {
//             return true;
//         }
//     }
//     return false;
// }



/* Tries to acquires LOCK and returns true if successful or false
   on failure.  The lock must not already be held by the current
   thread.

   This function will not sleep, so it may be called within an
   interrupt handler. */
bool
lock_try_acquire (struct lock *lock) {
	bool success;

	ASSERT (lock != NULL);
	ASSERT (!lock_held_by_current_thread (lock));

	success = sema_try_down (&lock->semaphore);
	if (success)
		lock->holder = thread_current ();
	return success;
}

/* Releases LOCK, which must be owned by the current thread.
   This is lock_release function.

   An interrupt handler cannot acquire a lock, so it does not
   make sense to try to release a lock within an interrupt
   handler. */
void 
lock_release(struct lock *lock) {
    ASSERT(lock != NULL);
    ASSERT(lock_held_by_current_thread(lock));

   //현재 락이 도네이터들의 락과 똑같다면 (곧 락을 풀꺼니까)
   //후원자 리스트에서 삭제한다.
   // 만약 후원 대상이 남았다면, 그 중에서 가장 큰 사람을 골라서
   // 나의 우선순위로 바꾸고, 없다면 원래의 우선순위로 돌아간다 !
  
    remove_donations_for_lock(lock); 
    reset_priority();                 

    lock->holder = NULL;
    sema_up(&lock->semaphore);
}


static void
remove_donations_for_lock(struct lock *lock){
	if(list_empty(&thread_current()->donations)) return;

    struct list_elem *target = list_begin(&thread_current()->donations);

    while (target != list_end(&thread_current()->donations)) {
        struct list_elem *next = list_next(target);  // next 먼저 저장
        struct thread *donator = list_entry(target, struct thread, d_elem);
		// 권장 삭제 방법을 통해 삭제함... 
		//for문 썻다가 커널 패닉으로 겁나게 혼났음.
        if (donator->wait_on_lock == lock) {
            list_remove(target);  
        }

        target = next;
    }
}

void 
reset_priority(void) {
    struct thread *curr = thread_current();

    int max_priority = curr->original_priority;

    // 남아 있는 도네이터 중 가장 높은 priority를 반영
    if (!list_empty(&curr->donations)) {
        struct list_elem *target;
        for (target = list_begin(&curr->donations); target != list_end(&curr->donations); target = list_next(target)) {
            struct thread *donator = list_entry(target, struct thread, d_elem);
            if (donator->priority > max_priority) {
                max_priority = donator->priority;
            }
        }
    }
    curr->priority = max_priority;
}

/* Returns true if the current thread holds LOCK, false
   otherwise.  (Note that testing whether some other thread holds
   a lock would be racy.) */
bool
lock_held_by_current_thread (const struct lock *lock) {
	ASSERT (lock != NULL);

	return lock->holder == thread_current ();
}

/* One semaphore in a list. */
struct semaphore_elem {
	struct list_elem elem;              /* List element. */
	struct semaphore semaphore;         /* This semaphore. */
};

/* Initializes condition variable COND.  A condition variable
   allows one piece of code to signal a condition and cooperating
   code to receive the signal and act upon it. */
void
cond_init (struct condition *cond) {
	ASSERT (cond != NULL);

	list_init (&cond->waiters);
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
cond_wait (struct condition *cond, struct lock *lock) {
	struct semaphore_elem waiter;

	ASSERT (cond != NULL);
	ASSERT (lock != NULL);
	ASSERT (!intr_context ());
	ASSERT (lock_held_by_current_thread (lock));
	
	sema_init (&waiter.semaphore, 0);
	list_push_back(&cond->waiters, &waiter.elem);
	lock_release (lock);
	sema_down (&waiter.semaphore);
	lock_acquire (lock);
}

// condition variable에서 semaphore_elem의 내부 waiters 중 가장 높은 priority를 기준으로 비교
static bool cmp_sema_priority(const struct list_elem *a, const struct list_elem *b, void *aux UNUSED) {
  struct semaphore_elem *sema_a = list_entry(a, struct semaphore_elem, elem); 
  struct semaphore_elem *sema_b = list_entry(b, struct semaphore_elem, elem);

  // 리스트가 비어 있으면 우선순위를 가장 낮게 취급
  // 둘 중 하나라도 empty면 비교가 불가능하니까, 우선순위가 없는 쪽은 무조건 뒤로 가도록 처리
   if (list_empty(&sema_a->semaphore.waiters)) return false;
   if (list_empty(&sema_b->semaphore.waiters)) return true;

  struct thread *thread_a = list_entry(list_front(&sema_a->semaphore.waiters), struct thread, elem);
  struct thread *thread_b = list_entry(list_front(&sema_b->semaphore.waiters), struct thread, elem);
  return thread_a->priority > thread_b->priority;
}


/* If any threads are waiting on COND (protected by LOCK), then
   this function signals one of them to wake up from its wait.
   LOCK must be held before calling this function.

   An interrupt handler cannot acquire a lock, so it does not
   make sense to try to signal a condition variable within an
   interrupt handler. */

void
cond_signal (struct condition *cond, struct lock *lock UNUSED) {
	ASSERT (cond != NULL);
	ASSERT (lock != NULL);
	ASSERT (!intr_context ());
	ASSERT (lock_held_by_current_thread (lock));

	if (!list_empty (&cond->waiters)){
		list_sort (&cond->waiters, cmp_sema_priority, NULL);
		sema_up (&list_entry (list_pop_front (&cond->waiters),
					struct semaphore_elem, elem)->semaphore);
	}
}


/* Wakes up all threads, if any, waiting on COND (protected by
   LOCK).  LOCK must be held before calling this function.

   An interrupt handler cannot acquire a lock, so it does not
   make sense to try to signal a condition variable within an
   interrupt handler. */
void
cond_broadcast (struct condition *cond, struct lock *lock) {
	ASSERT (cond != NULL);
	ASSERT (lock != NULL);

	while (!list_empty (&cond->waiters))
		cond_signal (cond, lock);
}


bool
cmp_sema_priority(const struct list_elem *a_, const struct list_elem *b_, void *aux UNUSED) {
  struct semaphore_elem *a = list_entry(a_, struct semaphore_elem, elem);
  struct semaphore_elem *b = list_entry(b_, struct semaphore_elem, elem);

  struct thread *thread_a = list_entry(list_front(&a->semaphore.waiters), struct thread, elem);
  struct thread *thread_b = list_entry(list_front(&b->semaphore.waiters), struct thread, elem);

  return thread_a->priority > thread_b->priority;
}