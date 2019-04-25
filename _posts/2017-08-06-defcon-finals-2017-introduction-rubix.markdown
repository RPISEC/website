---
title: DEFCON Finals 2017 - Intro & Rubix
authors: Toshi Piazza
date: 2017-08-06 13:50:17 -0400
categories: binary-exploitation
---

Over the weekend, July 28-31 2017 RPISEC competed with Lab RATs and Techsec in DEFCON
Finals, one of the most important CTFs of every year. Only 15 teams in the world get to
qualify for the event each year, and our team under Lab RATs was able to earn the right to
compete among 14 other globally professional teams.

This writeup covers the first challenge presented at DEFCON Finals, which kept us on our
toes throughout the competition. It was deceptively simple, and also served as an
introduction to cLEMENCy, a terrifying 9-bit middle endian architecture, as well as to the
toolchain that was used to create all future binaries.

The majority of this writeup will involve getting our feet wet with cLEMENCy while setting
up a comfortable environment for reverse engineering the later challenges released at
DEFCON.

### DEFCON Challenge Format

A link to the challenge binary can be found [here]({filename}/assets/16_rubix.bin)

For the CTF we are given only an emulator and a debugger to solve each of the challenges;
these challenges are compiled for a 9-bit middle endian architecture, cLEMENCy. When we
first run the rubix challenge under this emulator, we note that only garbage gets printed
to the terminal. This output doesn't change each run, and it's puzzling what exactly this
is. What if it's the emulator printing out 9-bit ascii instead of 8? Indeed, when we
transform from 9-bit to 8-bit between the debugger and our terminal, we end up with the
following:

```
This service implements a rubix cube. Solve the cube and win.

Give me 54 Bytes(ie: 53,12,5,etc): <input 54 comma-delimited chars>

                Top

             R6 R7 B0
             L1 T4 R5
             A0 B7 R2

  Left         Front       Right       Back

L8 L7 L0     T0 A7 F0    R8 F3 L6    B6 T3 T6
T5 L4 B1     F7 F4 A1    T1 R4 T7    F1 A4 R1
B8 B3 F8     A6 R3 L2    T2 L3 B2    R0 L5 A8

              Bottom
             A2 F5 F6
             B5 B4 A3
             T8 A5 F2


Action(U,U',D,D',L,L',R,R',F,F',B,B'):
```

Note that for the input too, we must transform the 54 comma-delimited 9-bit integers from
8-bit ascii to 9-bit ascii. Because interacting with the emulator was so painful yet so
crucial to all challenges hereafter, we wrote our own internal 9-bit to 8-bit translator
stand-in for netcat, dubbed cLEMnc.

### Symbolizing LibC

Before we go any further, we attempt to dig into the code. First, we note the following
strings in the binary (using a tool which specifically searches for ascii strings in 9-bit
format):

```
memtst %d %d  %ld
memtst: increase MEMTSTSZ
memtstleak %8p %8ld %s
memtstfail %8ld %s
memtstfree %8p %s
```

... among many other strings. However, these strings are present in almost every
binary--it's natural to assume that there exists a libc somewhere which is shared between
all challenges. Searching for these strings gives us a link to [neatlibc](https://github.com/aligrudi/neatlibc):
it turns out that starting at address 0x60 (in this binary), we can work our way up from
atoi, as each function in the binary is in exactly the same order as that specified in the
enclosing file, with each file being compiled in lexicographic order. For example, atoi is
immediately followed by atol (see atoi.c), followed by isascii, isblank, etc (from
ctypes.c). With a few exceptions, we are able to symbolize all of libc for all future
challenges, as functions are defined immediately one after the other, with no gaps. The
full script can be found [here](https://gist.github.com/toshipiazza/26ea6a6ed322ef79b4c80986fd94d376).

Thanks to Kareem (irc: krx) for developing the majority of the binja script!

Alternatively, we could consider a more generic approach which takes advantage of flare or
flirt signatures, but our quick and dirty script worked on all the challenges anyway.

### Analyzing Rubix

We now start disassembling from address 0, which is similar to `_start` on more familiar
platforms; this start template is closely shared among all challenges, with slight
variation.

[gist:id=c6ba96bc274eafe6bd939a81ee490a34]

This second car to `0x5fd0` turns out to be the call to `main`, whereas `0x8b4` is simply
setting up some state. In binaries for which the stack grows in the opposite direction
(weird, right?) `_start` looks slightly larger, but still has the same structure.

Manually combing through main, we see the following:

[gist:id=5c55b4316715728dda16b76b8103717c]

The binary maintains 3 cubes throughout the program: `cube1` and `cube2` are initially set
directly to our input. `cube3` is only used for printing out the cube and can be ignored,
and is also not seen in the main function.

After our call to `srand()`, we perform a random shuffle on `cube1`, shown below:

[gist:id=d68b573022450f0f58543040b1b2eeda]

This randomly performs actions on `cube1` and `cube3` in such a way that the resulting
cube is always solvable. Then, the program enters a read loop to parse an action and
perform it on cube1 (`PerformAction()`); once `cube1` matches `cube2` (which was
initialized to our custom input and never touched again), that means we've solved the
puzzle and are now able to execute it as shellcode.

### Exploitation

We would like to execute arbitrary shellcode that fits into 54 bytes. It turns out that
because `RandomShuffle()` performs only valid actions on `cube1`, we can always reverse
this by simply knowing the seed, which is in fact the first three numbers we give it,
converted to a trie. A valid solution script, which recieves shellcode and returns the
actions which need to be performed to solve the cube is shown below (minus the IO
portion):

[gist:id=e12b03feef5966737bd561b5c42b1cc7]

The given bytes should be interpreted as valid shellcode which prints out the flag (e.g.
`printf(0x401000)`). The example shellcode used in the example above disassembles to the
following:

[gist:id=849f3e640dd81225ce8e4cb00775c757]

### Recommended Patch

Unfortunately, DEFCON Finals requires much more past the initial exploit; we need to patch
our own services in a way that does not violate the service check, and in a way that
disrupts all future exploits from other teams. This is challenging, because we are unable
to simply kill the call to mprotect or the call to the user's shellcode; the service check
likely depends on being able to run shellcode, even if it does not necessarily have to
print out the flag.

Fortunately, LegitBS dropped us a nice hint in the binary in the form of
`FilterFunction()`, shown below:

[gist:id=cbd644a2fafaa494173b76709aa97292]

Clearly, we're being asked to "filter" the globally stored shellcode, and insert it into
this huge code cave. In other words, to completely patch the program, we are asked to
write a static or dynamic shellcode analyzer to filter out shellcode which could
potentially leak the flag. Hideous!

Unfortunately, neither our team nor any others wrote a full static analyzer within the
time constraints, and every patch was circumventable. By the third day, Lab RATs had
accumulated a working shellcode for every individual patch, so we were consistently
popping flags on all other teams. As a result, this challenge kept everyone on their toes
the entire competition.
