---
title: NorthSec 2017 rao_bash
authors: Toshi Piazza
date: 2017-05-23
categories: reverse-engineering 
---

This is a posthumous writeup of the rao_bash challenge hosted by NorthSec 2017. It
features a recompiled and backdoored bash with a broken ELF header. This was solved after
the CTF, because a small hint was dropped to us afterwards.

## Fixing the ELF Header

First and foremost, we’d like to fix the ELF header of the executable. This ELF header
interferes with all of our tools, and even the venerable file is having trouble with it:

```
$ file ./rao_bash_orig
./rao_bash_orig: ELF 64-bit MSB *unknown arch 0x3e00* (SYSV)
```

If that’s not enough of a hint, `readelf` seems to think that the entrypoint is some very
large number,

```
$ readelf -a ./rao_bash_orig
ELF Header:
  Magic:   7f 45 4c 46 02 02 01 00 00 00 00 00 00 00 00 00
  Class:                             ELF64
  Data:                              2's complement, big endian
 ...
  Machine:                           <unknown>: 0x3e00
  Version:                           0x1000000
  Entry point address:               0x300c420000000000
...
```

At this point, it should be obvious that the entry point is correct, if interpreted in big
endian, and `readelf` is so nice to show as much that the data itself is all big endian.
We simply revert this by flipping the "\x02" to a "\x01" in the 5th byte of the ELF header
(see the magic line). Now, all of our tools work as appropriate.

## Reversing

Here is where the hint comes into place: bash is a huge executable, and unfortunately we
could not find anything largely different between `rao_bash` and a bash we compiled
ourselves with a similar compiler version, i.e. by using diaphora. However, it seems we
missed a very quick-and-dirty xor, as seen below in the main function.

![Quick and dirty xor]({{ site.baseurl }}/assets/rao_bash_xor.png)

It looks like argv is checksummed, and if the checksum is valid it moves to
`sh_login_init()`. Obviously, we don’t quite care about the checksum, as it’s very lossy
and the interesting stuff is really happening in `sh_login_init()`. 

Unfortunately, everything after this is a little hairy; the disassembly involves
self-modifying code, slightly obscured control flow and finally a reversing function that
doesn’t decompile well. For testing purposes, we jump right into this function by marking
it as the entrypoint, i.e. with `rabin2 -O e/0x46390d ./rao_bash_entry`. This jumps
immediately into the code (which importantly is completely independent), and reveals some
more to us about the program.

```
$ ./rao_bash_entry
Welcome home RAO
Would you like to destroy the planet today?
Enter the supreme Password:<whatever>
zsh: segmentation fault (core dumped)  ./rao_bash
```

For starters, `sh_login_init()` immediately copies 90 bytes of the data section onto the
stack, jumping to it. It then proceeds to xor the next 700 bytes of the data section with
0xcf, and of course jumps into that. This section is quite interesting; the disassembly is
slightly obfuscated, in that it flattens control flow by introducing a dispatch basic
block, as reproduced below, symbolized to obviate the meaning of offsets, etc.

```assembly
  lea r15, dispatch
  xor r14, r14
  mov r14w, write_prep1 - dispatch
dispatch:
  add r14, r15
  push r14
  ret
```

Here, the dispatch basic block will jump to any offset from itself, where the offset is
stored in `r14` and the address of dispatch is stored in `r15`. This is used to implement
the reading and writing, as below.

```assembly
 write_prep1:
  xor rdx, rdx
  call write_prep2
welcome_msg: db "Welcome home RAO", 0xa, ...
write_prep2:  
  pop rsi
  mov dl,  0x5a ; sizeof welcome_msg
  mov r14, write - dispatch 
  mov r13, read  - dispatch
  push r15      ; jump back to dispatch
  ret
write:
  ...
  mov r14, r13  ; prepare to jump to read
  push r15      ; jump back to dispatch
  ret
read:
  ...
  jnz verify_input
  ...
```

Here, read pulls 32 bytes from the user and places them onto the stack, crashing if read
failed (by jumping into another instruction). Then, we immediately begin verifying the
user input, as below:

![CFG for main read loop]({{ site.baseurl }}/assets/rao_bash_cfg.jpeg)

Here, we see some obfuscation techniques at hand as well, notably the use of the rdrand
instruction to generate some random values which are xor’d with the hashed user input.
However, this is only there to thwart static analysis tools like binary ninja (which does
not currently parse the instruction as of this writing), as well as some other nifty tools
like angr. Furthermore, the effects of this instruction are reverted because we redo the
xor on the hashed user input with these random values before checking against the global
checksum data. Thus, it’s safe to ignore this in our analysis.

As for the rest of the verification function, it can be easily mimicked with the following
python code:

```py
def enc_byte(byte):
    lzcnt = float(64 - len(bin(byte)[2:]))
    byte  = float(byte)
    xmm0  = float(lzcnt) / float(byte)
    xmm0  =  float_to_int(xmm0)
    xmm0 ^=  float_to_int(lzcnt)
    return c_uint32(xmm0).value
enc = [ 0x44444444, 0xD60864B9, 0xD83BA686, 0x89D89D8A,
        0x38E38E39, 0xEA0EA0EA, 0x33333333, 0x32323232,
        0xE1E1E1E2, 0x97829CBC, 0xffffffffffffffff,
        0xE54975FC, 0x97829CBC, 0x31DEC0D5, 0xE54975FC,
        0x89D89D8A ]
for j,i in zip(enc, user_input)[::-1]:
    if j == 0xffffffffffffffff:
        j = -j - 1
        j = c_ulonglong(j).value
    if enc_byte(ord(i)) != j:
        crash()
```

Now, we simply have to brute the password, character by character until we get the full
flag, `4sM1sl1f3_Fl4gzZ`.
