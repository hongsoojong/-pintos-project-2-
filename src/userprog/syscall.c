#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "filesys/off_t.h"
#include "devices/block.h"
#include "devices/shutdown.h"
#include "devices/input.h"
#include "userprog/process.h"

struct lock filesys_lock;

struct file
  {
    struct inode *inode;        /* File's inode. */
    off_t pos;                  /* Current position. */
    bool deny_write;            /* Has file_deny_write() been called? */
  };

static void syscall_handler (struct intr_frame *);
void check_user_vaddr(const void *vaddr);

void syscall_init (void);
void halt(void);
void exit (int status);
pid_t exec (const char *cmd_line);
int wait (pid_t pid);
bool create(const char *file, unsigned initial_size);
bool remove (const char *file);
int open (const char *file);
int filesize (int fd);
int read (int fd, void* buffer, unsigned size);
int write (int fd, const void *buffer, unsigned size);
void seek (int fd, unsigned position);
unsigned tell (int fd);
void close (int fd);


void
syscall_init (void) 
{
  lock_init(&filesys_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler(struct intr_frame *f UNUSED)
{
    // printf("system call number : %d\n", *(uint32_t *)(f->esp));
    // printf ("system call!\n");

    void *sp = f->esp;

    switch (*(uint32_t *)sp)
    {
    case SYS_HALT: // args number: 0
        halt();
        break;

    case SYS_EXIT: // args number: 1
        check_user_vaddr(sp + 4);
        exit(*(uint32_t *)(sp + 4));
        break;

    case SYS_EXEC: // args number: 1
        check_user_vaddr(sp + 4);
        f->eax = exec((const char *)*(uint32_t *)(sp + 4));
        break;

    case SYS_WAIT: // args number: 1
        check_user_vaddr(sp + 4);
        f->eax = wait((pid_t *)*(uint32_t *)(sp + 4));
        break;

    case SYS_CREATE: // args number: 2
        check_user_vaddr(sp + 4);
        f->eax = create((const char *)*(uint32_t *)(sp + 4), (const char *)*(uint32_t *)(sp + 8));
        break;

    case SYS_REMOVE: // args number: 1
        check_user_vaddr(sp + 4);
        f->eax = remove((const char *)*(uint32_t *)(sp + 4));
        break;

    case SYS_OPEN: // args number: 1
        check_user_vaddr(sp + 4);
        f->eax = open((const char *)*(uint32_t *)(sp + 4));
        break;

    case SYS_FILESIZE: // args number: 1
        check_user_vaddr(sp + 4);
        f->eax = filesize((int)*(uint32_t *)(sp + 4));
        break;

    case SYS_READ: // args number: 3
        check_user_vaddr(sp + 4);
        f->eax = read((int)*(uint32_t *)(sp + 4), (void *)*(uint32_t *)(sp + 8), (unsigned)*((uint32_t *)(sp + 12)));
        break;

    case SYS_WRITE: // args number: 3
        check_user_vaddr(sp + 4);
        f->eax = write((int)*(uint32_t *)(sp + 4), (void *)*(uint32_t *)(sp + 8), (unsigned)*((uint32_t *)(sp + 12)));
        break;

    case SYS_SEEK: // args number: 2
        check_user_vaddr(sp + 4);
        seek((int)*(uint32_t *)(sp + 4), (unsigned)*((uint32_t *)(sp + 8)));
        break;

    case SYS_TELL: // args number: 1
        check_user_vaddr(sp + 4);
        f->eax = tell((int)*(uint32_t *)(sp + 4));
        break;

    case SYS_CLOSE: // args number: 1
        check_user_vaddr(sp + 4);
        close((int)*(uint32_t *)(sp + 4));
        break;
    }
    // thread_exit ();
}

void halt(void)
{
    shutdown_power_off();
}

void exit (int status) {
  int i;
  printf("%s: exit(%d)\n", thread_name(), status);
  thread_current()->exit_status = status;
  for (i = 3; i < 128; i++) {
      if (thread_current()->fd[i] != NULL) {
          close(i);
      }   
  }  
  thread_exit ();
}

pid_t exec (const char *cmd_line)
{
  return process_execute (cmd_line);
}

int wait (pid_t pid)
{
  return process_wait (pid);
}

bool create(const char *file, unsigned initial_size) {
  if (file == NULL)
    exit(-1);
  check_user_vaddr(file);
  return filesys_create (file, initial_size);
}

bool remove (const char *file) {
  if (file == NULL)
    exit(-1);
  check_user_vaddr(file);
  return filesys_remove (file);
}

int open (const char *file) {
  int i;
  struct file* fp;
  if (file == NULL) {
      exit(-1);
  }
  check_user_vaddr(file);
  fp = filesys_open(file);
  if (fp == NULL) {
      return -1; 
  } else {
    for (i = 3; i < 128; i++) {
      if (thread_current()->fd[i] == NULL) {
        if (strcmp(thread_current()->name, file) == 0) {
            file_deny_write(fp);
        }
        thread_current()->fd[i] = fp; 
        return i;
      }   
    }   
  }
  return -1; 
}

int filesize (int fd) {
  if (thread_current()->fd[fd] == NULL) {
      exit(-1);
  }
  return file_length(thread_current()->fd[fd]);
}

int read (int fd, void* buffer, unsigned size) {
  int i;
  int ret;
  check_user_vaddr(buffer);
  lock_acquire(&filesys_lock);
  if (fd == 0) {
    for (i = 0; i < size; i ++) {
      if (((char *)buffer)[i] == '\0') {
        break;
      }
    }
    ret = i;
  } else if (fd > 2) {
    if (thread_current()->fd[fd] == NULL) {
      exit(-1);
    }
    ret = file_read(thread_current()->fd[fd], buffer, size);
  }
  lock_release(&filesys_lock);
  return ret;
}

int write (int fd, const void *buffer, unsigned size) {
  int ret = -1;
  check_user_vaddr(buffer);
  lock_acquire(&filesys_lock);
  if (fd == 1) {
    putbuf(buffer, size);
    ret = size;
  } else if (fd > 2) {
    if (thread_current()->fd[fd] == NULL) {
      lock_release(&filesys_lock);
      exit(-1);
    }
    if (thread_current()->fd[fd]->deny_write) {
        file_deny_write(thread_current()->fd[fd]);
    }
    ret = file_write(thread_current()->fd[fd], buffer, size);
  }
  lock_release(&filesys_lock);
  return ret;
}

void seek (int fd, unsigned position) {
  if (thread_current()->fd[fd] == NULL) {
    exit(-1);
  }
  file_seek(thread_current()->fd[fd], position);
}

unsigned tell (int fd) {
  if (thread_current()->fd[fd] == NULL) {
    exit(-1);
  }
  return file_tell(thread_current()->fd[fd]);
}

void close (int fd) {
  struct file* fp;
  if (thread_current()->fd[fd] == NULL) {
    exit(-1);
  }
  fp = thread_current()->fd[fd];
  thread_current()->fd[fd] = NULL;
  return file_close(fp);
}

void check_user_vaddr(const void *vaddr)
{
    // ASSERT(is_user_vaddr(vaddr));
    // ASSERT로 하면 프로세스가 -1로 종료되지 않아서 테스트케이스 통과 안함
    if (!is_user_vaddr(vaddr))
        exit(-1);
}
