---
title: Boston Key Party 2017
authors: Mike Macelletti
date: 2017-02-27
categories: binary-exploitation
---

This is a writeup for the pwn 200 binary exploitation challenge "hiddensc" we solved during Boston Key Party 2017.

>I know I hid that pesky shellcode page somewhere… (the hidden page will change every ~~10~~ 20 minutes). Please don't brute force the hundreds of GB of space…

### First Look

#### Running the Binary

We're given two files, hiddensc which is the binary, and poop.sc, which is the shellcode that runs /bin/sh. Looking at the challenge description, it appears the program puts the shellcode somewhere in memory.

Running the binary locally on port 9001 gives us the following output:

```
$ ./hiddensc 9001

seeding with 942fa402
[!] shellcode is at 0x2fa5a2820000
[!] page size is 0x1000
[!] pid is 29166
[+] listening on 0.0.0.0 9001
```

Running subsequent times shows the shellcode does move around and is exactly one page (0x1000 bytes) long. Presumably we want somehow return to the shellcode which will give us a shell on the server.

#### Main Menu

After we have the binary running on a port we can interact with it. The program is seemingly quite simple

```
$ nc localhost 9001

[a]lloc, [j]ump : 
```

We have two options, alloc and jump. Testing each option shows alloc will malloc an array of the size we request and jump will set RIP to the address we give. We also have the option to free the array we allocate, but if we choose not to we cannot free it later.

```
[a]lloc, [j]ump : a
sz? 1234
free? n

[a]lloc, [j]ump : j
sz? 1094795585
Stopped reason: SIGSEGV
0x0000000041414141 in ?? ()
```

Running the binary in gdb and connecting shows the program does let us jump to any address we want. Problem is the shellcode moves around every 20 minutes on the remote server, and we can't possibly bruteforce the entire 64-bit address space.

### Initial Reverse Engineering

#### Static Analysis

From here I starting reverse engineering the binary in GDB. First I took a look at the randomness to see if there was a way to predict where the shellcode ended up in memory. A few lines in main stood out to me as being relevant to how the program picked an address to place the shellcode at.

```
0x5555555554aa <+157>:	call   0x5555555559bd <do_srand>
0x5555555554af <+162>:	call   0x5555555553b5 <rand64>

...

0x5555555554d7 <+202>:	movabs rdx,0x555555555555
0x5555555554e1 <+212>:	imul   rax,rdx
0x5555555554e5 <+216>:	sub    rcx,rax
0x5555555554e8 <+219>:	mov    rax,rcx
0x5555555554eb <+222>:	mov    edx,DWORD PTR [rbp-0x45c]
0x5555555554f1 <+228>:	neg    edx
0x5555555554f3 <+230>:	movsxd rdx,edx
0x5555555554f6 <+233>:	and    rax,rdx
0x5555555554f9 <+236>:	mov    QWORD PTR [rbp-0x448],rax

...

0x55555555556e <+353>:	movsxd rsi,eax    # Length (0x1000)
0x555555555571 <+356>:	mov    rax,QWORD PTR [rbp-0x448]
0x555555555578 <+363>:	mov    edx,DWORD PTR [rbp-0x458]
0x55555555557e <+369>:	mov    r9d,0x0    # Offset
0x555555555584 <+375>:	mov    r8d,edx    # fd
0x555555555587 <+378>:	mov    ecx,0x2    # Flags
0x55555555558c <+383>:	mov    edx,0x5    # Protections
0x555555555591 <+388>:	mov    rdi,rax    # Address
0x555555555594 <+391>:	call   0x555555554f40 <mmap@plt>
```

Based on the assembly it looks like the shellcode is placed at a random address between 0x0 and 0x555555555555 or so. The program mmaps a page with execute permissions and puts the shellcode there.

#### Dynamic Analysis

To start the dynamic analysis, I first took a look at the layout of memory to see how the shellcode page fit in with everything else in memory.

```
gdb-peda$ info proc mappings
process 29175
Mapped address spaces:

          Start Addr           End Addr       Size     Offset objfile
      0x2fa5a2820000     0x2fa5a2821000     0x1000        0x0 /home/.../poop.sc
      0x555555554000     0x555555556000     0x2000        0x0 /home/.../hiddensc
      0x555555756000     0x555555757000     0x1000     0x2000 /home/.../hiddensc
      0x555555757000     0x555555758000     0x1000     0x3000 /home/.../hiddensc
      0x555555758000     0x555555779000    0x21000        0x0 [heap]
      0x7ffff71da000     0x7ffff71e4000     0xa000        0x0 /lib/x86_64-linux-gnu/libnss_files-2.19.so
      0x7ffff71e4000     0x7ffff73e3000   0x1ff000     0xa000 /lib/x86_64-linux-gnu/libnss_files-2.19.so
      0x7ffff73e3000     0x7ffff73e4000     0x1000     0x9000 /lib/x86_64-linux-gnu/libnss_files-2.19.so
      0x7ffff73e4000     0x7ffff73e5000     0x1000     0xa000 /lib/x86_64-linux-gnu/libnss_files-2.19.so
      0x7ffff73e5000     0x7ffff73f0000     0xb000        0x0 /lib/x86_64-linux-gnu/libnss_nis-2.19.so
      0x7ffff73f0000     0x7ffff75ef000   0x1ff000     0xb000 /lib/x86_64-linux-gnu/libnss_nis-2.19.so
      0x7ffff75ef000     0x7ffff75f0000     0x1000     0xa000 /lib/x86_64-linux-gnu/libnss_nis-2.19.so
      0x7ffff75f0000     0x7ffff75f1000     0x1000     0xb000 /lib/x86_64-linux-gnu/libnss_nis-2.19.so
      0x7ffff75f1000     0x7ffff7608000    0x17000        0x0 /lib/x86_64-linux-gnu/libnsl-2.19.so
      0x7ffff7608000     0x7ffff7807000   0x1ff000    0x17000 /lib/x86_64-linux-gnu/libnsl-2.19.so
      0x7ffff7807000     0x7ffff7808000     0x1000    0x16000 /lib/x86_64-linux-gnu/libnsl-2.19.so
      0x7ffff7808000     0x7ffff7809000     0x1000    0x17000 /lib/x86_64-linux-gnu/libnsl-2.19.so
      0x7ffff7809000     0x7ffff780b000     0x2000        0x0 
      0x7ffff780b000     0x7ffff7814000     0x9000        0x0 /lib/x86_64-linux-gnu/libnss_compat-2.19.so
      0x7ffff7814000     0x7ffff7a13000   0x1ff000     0x9000 /lib/x86_64-linux-gnu/libnss_compat-2.19.so
      0x7ffff7a13000     0x7ffff7a14000     0x1000     0x8000 /lib/x86_64-linux-gnu/libnss_compat-2.19.so
      0x7ffff7a14000     0x7ffff7a15000     0x1000     0x9000 /lib/x86_64-linux-gnu/libnss_compat-2.19.so
      0x7ffff7a15000     0x7ffff7bcf000   0x1ba000        0x0 /lib/x86_64-linux-gnu/libc-2.19.so
      0x7ffff7bcf000     0x7ffff7dcf000   0x200000   0x1ba000 /lib/x86_64-linux-gnu/libc-2.19.so
      0x7ffff7dcf000     0x7ffff7dd3000     0x4000   0x1ba000 /lib/x86_64-linux-gnu/libc-2.19.so
      0x7ffff7dd3000     0x7ffff7dd5000     0x2000   0x1be000 /lib/x86_64-linux-gnu/libc-2.19.so
      0x7ffff7dd5000     0x7ffff7dda000     0x5000        0x0 
      0x7ffff7dda000     0x7ffff7dfd000    0x23000        0x0 /lib/x86_64-linux-gnu/ld-2.19.so
      0x7ffff7fcf000     0x7ffff7fd2000     0x3000        0x0 
      0x7ffff7ff6000     0x7ffff7ff8000     0x2000        0x0 
      0x7ffff7ff8000     0x7ffff7ffa000     0x2000        0x0 [vvar]
      0x7ffff7ffa000     0x7ffff7ffc000     0x2000        0x0 [vdso]
      0x7ffff7ffc000     0x7ffff7ffd000     0x1000    0x22000 /lib/x86_64-linux-gnu/ld-2.19.so
      0x7ffff7ffd000     0x7ffff7ffe000     0x1000    0x23000 /lib/x86_64-linux-gnu/ld-2.19.so
      0x7ffff7ffe000     0x7ffff7fff000     0x1000        0x0 
      0x7ffffffde000     0x7ffffffff000    0x21000        0x0 [stack]
  0xffffffffff600000 0xffffffffff601000     0x1000        0x0 [vsyscall]
```

Based on the above output, it looks like the shellcode is always located above everything else in memory and it is unlikely there is anything else in memory nearby.

#### Initial Analysis Conclusions

Based on the initial analysis, it appears the problem is to find the location of the shellcode in memory which is randomized each time the binary is run and jump to it using only malloc to leak information.

### Leaking Information

#### Feedback

The only way to leak information from the program is to use the information it gives as feedback over the socket. The most definitive and useful information it supplies is whether or not malloc succeeds. This is the attack vector I chose to leak the address of the shellcode.

#### malloc

malloc will fail if the program cannot allocate the space in memory that is requested. The only reason this would happen during normal operation of this program is if there is not a large enough continuous space in memory to meet the request.

This means it would be possible to leak the largest continuous space in memory by attempting to allocate an area in memory that the program cannot possibly create and then slowing lowering the size of the allocation until it succeeds.

#### Large Allocations

The problem is the largest continuous space in memory is about 2^48 bytes in size, or ~300 terabytes. The operating system can't possibly let us allocate something this large, and a local test confirms this.

```
[a]lloc, [j]ump : a
sz? 8589934592
FAIL
[a]lloc, [j]ump : a
sz? 4294967296
free? 
```

In the above session we can see 8589934592 (2^33) fails while 4294967296 (2^32) succeeds. Somewhere between those two numbers is the amount of RAM on my machine, so clearly the operating system is rejecting an allocation so large that the system cannot possibly use it. However, testing on the remote server shows something interesting.

```
[a]lloc, [j]ump : a
sz? 281474976710656
free? 
```

Somehow TB allocations are allowed remotely but not on my machine. Unless they secured all the RAM in the world, there must be some way to tell the operating system not to reject allocations greater than the total amount of memory available.

#### Memory Overcommitment

After some searching, I found the setting they must have used on their server to allow for larger allocations, overcommit_memory. The default setting of 0 will do some basic checking on the size of allocations, but setting the value to 1 will not do any checking, which is what we want.

```
## echo 1 > /proc/sys/vm/overcommit_memory
```

After changing this setting, allocations as large as 2^48 work locally just like on the remote server. This means developing a solution locally is possible

### Developing a Solution

#### Strategy

Looking back at the map of memory from GDB, there are effectively three large open spaces in memory.

```
Mapped address spaces:

          Start Addr           End Addr       Size     Offset objfile
      0x2fa5a2820000     0x2fa5a2821000     0x1000        0x0 /home/.../poop.sc
      0x555555554000     0x555555556000     0x2000        0x0 /home/.../hiddensc
      ...
      0x555555758000     0x555555779000    0x21000        0x0 [heap]
      0x7ffff71da000     0x7ffff71e4000     0xa000        0x0 /lib/x86_64-linux-gnu/libnss_files-2.19.so
      ...
```

From 0x0 to 0x555555555555 is somewhere between 2^46 and 2^47 bytes, and 0x555555779000 to 0x7ffff71da000 is somewhere between 2^46 and 2^45 bytes. The shellcode can be mapped to anywhere inside the first empty space which will split it into two parts.

Let's see what happens if we create an allocation of size 2^32.

```
gdb-peda$ info proc mappings
process 1116
Mapped address spaces:

          Start Addr           End Addr       Size     Offset objfile
       0x4d4c10bd000      0x4d4c10be000     0x1000        0x0 /home/.../poop.sc
      0x555555554000     0x555555556000     0x2000        0x0 /home/.../hiddensc
      0x555555756000     0x555555757000     0x1000     0x2000 /home/.../hiddensc
      0x555555757000     0x555555758000     0x1000     0x3000 /home/.../hiddensc
      0x555555758000     0x555555779000    0x21000        0x0 [heap]
  --->0x7ffeeffff000     0x7ffff0000000 0x100001000       0x0 
      0x7ffff0000000     0x7ffff0021000    0x21000        0x0 
      0x7ffff0021000     0x7ffff4000000  0x3fdf000        0x0 
      0x7ffff71da000     0x7ffff71e4000     0xa000        0x0 /lib/x86_64-linux-gnu/libnss_files-2.19.so
      ...
```

It looks like malloc put the allocated memory at the bottom of memory, just above some of the libraries. Unfortunately this doesn't help with figuring out where the shellcode page is, but creating an allocation of size 2^45 bytes will fill up most of that space. This means allocations in the range 2^45 to 2^47 should be populated in the area around the shellcode page after the lower free space is taken up.

```
gdb-peda$ info proc mappings
process 4000
Mapped address spaces:

          Start Addr           End Addr       Size     Offset objfile
      0x2e2a14308000     0x4e2a14309000 0x200000001000    0x0 
      0x4e2a14309000     0x4e2a1430a000     0x1000        0x0 /home/.../poop.sc
      ...
      0x555555757000     0x555555758000     0x1000     0x3000 /home/.../hiddensc
      0x555555758000     0x555555779000    0x21000        0x0 [heap]
      0x5ffff71d9000     0x7ffff71da000 0x200000001000    0x0 
      0x7ffff71da000     0x7ffff71e4000     0xa000        0x0 /lib/x86_64-linux-gnu/libnss_files-2.19.so
      ...
```

#### Solution

So we can force the program to create allocations between 0x0 and the shellcode (which is the biggest space in memory), and we can see whether or not the allocations succeed (and free them if they do). This allows us to figure out the amount of space between 0x0 and the shellcode, which is effectively the address of the shellcode. From here it's just a binary search to find the maximum size allocation allowed.

#### 50% of the Time it Works Every Time

The only problem with the above strategy is sometimes (half the time) the shellcode is placed closer to 0x0 than the code section in memory. This means the biggest space (and the space the above binary search will find) will be between the code section and the shellcode. Unfortunately because of ASLR the code section moves around, so knowing the space between the code section and the shellcode won't help much.

Looking back on this problem, the solution would have been to not free the biggest allocation we could make (effectively taking up all the space between the code section and the shellcode), and then doing another binary search. However during the competition I instead chose to wait 20 minutes for the server to place the shellcode at a new location which was hopefully closer to the code section than to 0x0.

### Testing the Solution

#### Implementation

```hiddensc.py``` contains the code used to solve the problem. After some initial testing, the maximum size found by the binary search algorithm was consistently 16 or 17 pages smaller than the location of the shellcode. With this adjustment, it works after both possibilities are tried.

This is not a problem because the server only randomizes the shellcode location every 20 minutes. Both possibilities can be tried without having to recalculate the address of the shellcode.

### Flag

Connecting to the remote server and exploiting the binary gives a shell!

```
$ ls
flag
hiddensc
poop.sc
$ cat flag
bkp{really who actually turns on overcommit even in prod...}
```
