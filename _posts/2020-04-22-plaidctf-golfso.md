---
title: PlaidCTF 2020 golf.so
authors: Avi Weinstock
date: 2020-04-22
categories: misc elf-metadata
---

# Description
The challenge description linked to `golf.so.pwni.ng`, which had a scoreboard, and an upload page with the following instructions:

> Upload a 64-bit ELF shared object of size at most 1024 bytes. It should spawn a shell (execute execve("/bin/sh", ["/bin/sh"], ...)) when used like
> 
> `LD_PRELOAD=<upload> /bin/true`

# First attempt: C with `__attribute__((constructor))` (5992 bytes)

The `__attribute__((constructor))` mechanism allows binaries to run code before `main` (in the case of ordinary executables) or when being loaded (in the case of shared objects).

The following C goes into an infinite loop when loaded, for easy debugging relative to starting with shellcode:

```
// gcc -fPIC -shared tmp.c -Os && strip a.out
__attribute__((constructor))
void f(void) {
    for(;;) {}
}
```

It runs properly with `sh -c 'LD_PRELOAD=./a.out /bin/true'`, but is 5992 bytes; much too large for the challenge's requirement of 1024 bytes.

# Second attempt: Creating an ELF with structs (512 bytes)

Starting with a large binary and cutting it down seemed unappealing/risk-prone relative to manually creating an ELF from scratch, adding only the fields needed to get it to work.

I opted to use Rust with `cargo-script` as a lightweight runner, and with the `goblin` library for the ELF struct definitions.

Parts of the structure were straightforward to get right from reading `man 5 elf`, parts of the structure were determined via trial and error.
I debugged the linker in gdb with the following commands:

```
$ gdb sh
(gdb) set follow-fork-mode child
(gdb) r -c 'LD_PRELOAD=./libgolf2.so /bin/true'
```

## The ELF Header
Components were allocated heuristically at round numbers for ease of memorization (program headers at 128, shellcode at 256, dynamic section at 400).

`e_type` is `ET_DYN` for shared objects.
`e_entry` is `0x41410000` (page-aligned A's) + `0x100` (the offset of shellcode).

```
fn main() -> Result<(), anyhow::Error> {
    let e_ident = [0x7f, b'E', b'L', b'F', header::ELFCLASS64, header::ELFDATA2LSB, header::EV_CURRENT, header::ELFOSABI_NONE, 0, 0, 0, 0, 0, 0, 0, 0];
    let mut elfbytes = vec![0; 512];
    let header: &mut Header = unsafe { &mut *(elfbytes.as_mut_ptr() as *mut Header) };
    *header = Header {
        e_ident,
        e_type: header::ET_DYN,
        e_machine: header::EM_X86_64,
        e_version: header::EV_CURRENT as _,
        e_entry: 0x41410100,
        e_phoff: 128,
        e_shoff: 0,
        e_flags: 0,
        e_ehsize: mem::size_of::<Header>() as _,
        e_phentsize: mem::size_of::<ProgramHeader>() as _,
        e_phnum: 2,
        e_shentsize: mem::size_of::<SectionHeader>() as _,
        e_shnum: 0,
        e_shstrndx: 0,
    };
```

## The program headers

I ended up needing 2 program headers to get the equivalent of `__attribute__((constructor))` working, a `PT_LOAD` header and a `PT_DYNAMIC` header:

The `PT_LOAD` header says to map the data in the ELF as RWX, and determines the virtual address (0x41410000).

The `PT_DYNAMIC` header says where in the virtual space the dynamic section (which contains imporant metadata) is.

```
    let phdr: &mut ProgramHeader = unsafe { &mut *(elfbytes.as_mut_ptr().offset(128) as *mut ProgramHeader) };
    *phdr = ProgramHeader {
        p_type: Phdr::PT_LOAD,
        p_flags: Phdr::PF_R | Phdr::PF_W | Phdr::PF_X,
        p_offset: 0,
        p_vaddr: 0x41410000,
        p_paddr: 0x41410000,
        p_filesz: 512,
        p_memsz: 512,
        p_align: 0x1000,
    };
    let phdr2: &mut ProgramHeader = unsafe { &mut *(elfbytes.as_mut_ptr().offset(128).offset(mem::size_of::<ProgramHeader>() as _) as *mut ProgramHeader) };
    *phdr2 = ProgramHeader {
        p_type: Phdr::PT_DYNAMIC,
        p_flags: Phdr::PF_R | Phdr::PF_W | Phdr::PF_X,
        p_offset: 400,
        p_vaddr: 0x41410190,
        p_paddr: 0,
        p_filesz: mem::size_of::<dynamic::Dyn>() as _,
        p_memsz: mem::size_of::<dynamic::Dyn>() as _,
        p_align: 8,
    };
```

## The shellcode

To start with, I just allocated an infinite loop at offset 256.

```
    elfbytes[256] = 0xeb;
    elfbytes[257] = 0xfe;
```

## The dynamic section

`man 5 elf` gives a decent description of what the various `DT_*` commands do, but not which of them were needed. The symptom of having too few of these is the dynamic linker null-dereferencing in `_dl_relocate_object`, which isn't that helpful.

```
Thread 2.1 "true" received signal SIGSEGV, Segmentation fault.
[Switching to process 5534]
_dl_relocate_object (scope=0x7ffff7ff6358, reloc_mode=<optimized out>, consider_profiling=consider_profiling@entry=0) at dl-reloc.c:232
232     dl-reloc.c: No such file or directory.
(gdb) x/i $rip
=> 0x7ffff7de4821 <_dl_relocate_object+161>:    mov    0x8(%rax),%rax
(gdb) i r rax
rax            0x0      0
```

My teammate negasora (who was working on this challenge with a nasm-based approach) linked me some [documentation](https://docs.oracle.com/cd/E19683-01/817-3677/chapter6-42444/index.htm) that described `{DT_HASH, DT_STRTAB, DT_SYMTAB, DT_STRSZ, DT_SYMENT}` as mandatory.

`DT_HASH` caused a segfault if you didn't put in a valid address, but it turned out to not be needed after all.

`DT_INIT` pointing to the shellcode seems to be the key ingredient of `__attribute__((constructor))`. Apparently in a normal shared object, it points to code that walks a linked list of function pointers, but that's cruft that we don't need for this challenge.

```
    let dynamic = vec![
        // https://docs.oracle.com/cd/E19683-01/817-3677/chapter6-42444/index.html
        //dynamic::Dyn { d_tag: DT_HASH, d_val: 1 },
        dynamic::Dyn { d_tag: DT_INIT, d_val: 0x41410100 },
        dynamic::Dyn { d_tag: DT_STRTAB, d_val: 2 },
        dynamic::Dyn { d_tag: DT_SYMTAB, d_val: 3 },
        dynamic::Dyn { d_tag: DT_STRSZ, d_val: 0 },
        dynamic::Dyn { d_tag: DT_SYMENT, d_val: 0 },
        dynamic::Dyn { d_tag: DT_NULL, d_val: 0 },
    ];
    let dynamic_raw: &mut [dynamic::Dyn] = unsafe { std::slice::from_raw_parts_mut(elfbytes.as_mut_ptr().offset(400) as *mut dynamic::Dyn, dynamic.len()) };
    for (x, y) in dynamic.into_iter().zip(dynamic_raw.iter_mut()) {
        *y = x;
    }
```

## Writing it out to a file

The above code up to this point just creates the ELF in memory, this snippet writes it to a file, which complete's the generator's main.

```
    let mut file = File::create("libgolf2.so")?;
    file.write(&elfbytes)?;
    Ok(())
}
```

## Adding real shellcode

At this point, we have a working 512-bit ELF that goes into an infinite loop if you `LD_PRELOAD` it. The challenge wants us to run `execve("/bin/sh", ["/bin/sh"], NULL)`, so we add shellcode that does that:

```
<     elfbytes[256] = 0xeb;
<     elfbytes[257] = 0xfe;
---
> /*
>    0:   48 ba 2f 62 69 6e 2f    movabs $0x68732f6e69622f,%rdx
>    7:   73 68 00
>    a:   48 83 e8 10             sub    $0x10,%rax
>    e:   48 89 10                mov    %rdx,(%rax)
>   11:   48 89 c7                mov    %rax,%rdi
>   14:   48 31 d2                xor    %rdx,%rdx
>   17:   48 83 e8 08             sub    $0x8,%rax
>   1b:   48 89 10                mov    %rdx,(%rax)
>   1e:   48 83 e8 08             sub    $0x8,%rax
>   22:   48 89 38                mov    %rdi,(%rax)
>   25:   48 89 c6                mov    %rax,%rsi
>   28:   48 31 c0                xor    %rax,%rax
>   2b:   b0 3b                   mov    $0x3b,%al
>   2d:   0f 05                   syscall
> */
>     let shellcode = b"\x48\xba\x2f\x62\x69\x6e\x2f\x73\x68\x00\x48\x83\xe8\x10\x48\x89\x10\x48\x89\xc7\x48\x31\xd2\x48\x83\xe8\x08\x48\x89\x10\x48\x83\xe8\x08\x48\x89\x38\x48\x89\xc6\x48\x31\xc0\xb0\x3b\x0f\x05";
>
>     for (i, x) in shellcode.iter().enumerate() {
>         elfbytes[256+i] = *x;
>     }
```
At this point, we have the following 512 byte ELF:
```
$ xxd libgolf2.so
00000000: 7f45 4c46 0201 0100 0000 0000 0000 0000  .ELF............
00000010: 0300 3e00 0100 0000 0001 4141 0000 0000  ..>.......AA....
00000020: 8000 0000 0000 0000 0000 0000 0000 0000  ................
00000030: 0000 0000 4000 3800 0200 4000 0000 0000  ....@.8...@.....
00000040: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000050: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000060: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000070: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000080: 0100 0000 0700 0000 0000 0000 0000 0000  ................
00000090: 0000 4141 0000 0000 0000 4141 0000 0000  ..AA......AA....
000000a0: 0002 0000 0000 0000 0002 0000 0000 0000  ................
000000b0: 0010 0000 0000 0000 0200 0000 0700 0000  ................
000000c0: 9001 0000 0000 0000 9001 4141 0000 0000  ..........AA....
000000d0: 0000 0000 0000 0000 1000 0000 0000 0000  ................
000000e0: 1000 0000 0000 0000 0800 0000 0000 0000  ................
000000f0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000100: 48ba 2f62 696e 2f73 6800 4883 e810 4889  H./bin/sh.H...H.
00000110: 1048 89c7 4831 d248 83e8 0848 8910 4883  .H..H1.H...H..H.
00000120: e808 4889 3848 89c6 4831 c0b0 3b0f 0500  ..H.8H..H1..;...
00000130: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000140: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000150: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000160: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000170: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000180: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000190: 0c00 0000 0000 0000 0001 4141 0000 0000  ..........AA....
000001a0: 0500 0000 0000 0000 0200 0000 0000 0000  ................
000001b0: 0600 0000 0000 0000 0300 0000 0000 0000  ................
000001c0: 0a00 0000 0000 0000 0000 0000 0000 0000  ................
000001d0: 0b00 0000 0000 0000 0000 0000 0000 0000  ................
000001e0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
000001f0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
```

It's not worth a flag yet though, if we submit it, the website tells us:
```
You made it to level 0: non-trivial! You have 12 bytes left to be considerable. This effort is worthy of 0/2 flags.
```
# Trimming down the binary (288 bytes):

The generator up to this point used hardcoded offsets just to get it working.
It's clear from looking at the hexdump that there's a lot of empty space filled with zeros, so we can get some easy space savings by just parameterizing the offsets and reducing the gaps.

## Parameterizing offsets
```
65c65,69
<     let mut elfbytes = vec![0; 512];
---
>     let elf_size = 0x120;
>     let dyn_offset = 0xe0-6-1;
>     let shellcode_offset = 0xb0-6;
>     let phdr_offset = 0x40;
>     let mut elfbytes = vec![0; elf_size];
72,73c76,77
<         e_entry: 0x41410100,
<         e_phoff: 128,
---
>         e_entry: 0,
>         e_phoff: phdr_offset,
84c88
<     let mut phdr: &mut ProgramHeader = unsafe { &mut *(elfbytes.as_mut_ptr().offset(128) as *mut ProgramHeader) };
---
>     let mut phdr: &mut ProgramHeader = unsafe { &mut *(elfbytes.as_mut_ptr().offset(phdr_offset as _) as *mut ProgramHeader) };
91,92c95,96
<         p_filesz: 512,
<         p_memsz: 512,
---
>         p_filesz: elf_size as _,
>         p_memsz: elf_size as _,
96c100
<     let mut phdr2: &mut ProgramHeader = unsafe { &mut *(elfbytes.as_mut_ptr().offset(128).offset(mem::size_of::<ProgramHeader>() as _) as *mut ProgramHeader) };
---
>     let mut phdr2: &mut ProgramHeader = unsafe { &mut *(elfbytes.as_mut_ptr().offset(phdr_offset as _).offset(mem::size_of::<ProgramHeader>() as _) as *mut ProgramHeader) };
101c105
<         p_vaddr: 0x41410190,
---
>         p_vaddr: 0x41410000 + dyn_offset,
136c140
<         elfbytes[256+i] = *x;
---
>         elfbytes[shellcode_offset+i] = *x;
142c146
<         dynamic::Dyn { d_tag: DT_INIT, d_val: 0x41410100 },
---
>         dynamic::Dyn { d_tag: DT_INIT, d_val: 0x41410000+(shellcode_offset as u64) },
```

## Truncating the dynamic section off the end of the ELF
Together with these changes, there's a more involved one.
The dynamic section's `DT_NULL` is also zeros, and most of `DT_SYMENT` is zeros (it's the little-endian u64 0xb):
```
        dynamic::Dyn { d_tag: DT_SYMENT, d_val: 0 },
        dynamic::Dyn { d_tag: DT_NULL, d_val: 0 },
```
```
000001d0: 0b00 0000 0000 0000 0000 0000 0000 0000  ................
000001e0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
```
Since the linker maps a full page for the ELF, and they're zeroed by default, we can make the on-disk size smaller by just making the ELF size smaller.
To do that though, we need to change how we're writing the ELF (not writing the zero bytes) to avoid corrupting memory in our generator:

```
<     let mut dynamic_raw: &mut [dynamic::Dyn] = unsafe { std::slice::from_raw_parts_mut(elfbytes.as_mut_ptr().offset(400) as *mut dynamic::Dyn, dynamic.len()) };
<     for (x, y) in dynamic.into_iter().zip(dynamic_raw.iter_mut()) {
<         *y = x;
---
>     for (i, x) in unsafe { std::slice::from_raw_parts(dynamic.as_ptr() as *const u8, dynamic.len() * mem::size_of::<dynamic::Dyn>()) }.iter().enumerate() {
>         if *x != 0 {
>             elfbytes[(dyn_offset as usize)+i] = *x;
>         }
>     }
```

## First flag
We now have a 288 byte ELF:
```
$ xxd ./libgolf2.so
00000000: 7f45 4c46 0201 0100 0000 0000 0000 0000  .ELF............
00000010: 0300 3e00 0100 0000 0000 0000 0000 0000  ..>.............
00000020: 4000 0000 0000 0000 0000 0000 0000 0000  @...............
00000030: 0000 0000 4000 3800 0200 4000 0000 0000  ....@.8...@.....
00000040: 0100 0000 0700 0000 0000 0000 0000 0000  ................
00000050: 0000 4141 0000 0000 0000 4141 0000 0000  ..AA......AA....
00000060: 2001 0000 0000 0000 2001 0000 0000 0000   ....... .......
00000070: 0010 0000 0000 0000 0200 0000 0700 0000  ................
00000080: 9001 0000 0000 0000 d900 4141 0000 0000  ..........AA....
00000090: 0000 0000 0000 0000 1000 0000 0000 0000  ................
000000a0: 1000 0000 0000 0000 0800 48ba 2f62 696e  ..........H./bin
000000b0: 2f73 6800 4883 e810 4889 1048 89c7 4831  /sh.H...H..H..H1
000000c0: d248 83e8 0848 8910 4883 e808 4889 3848  .H...H..H...H.8H
000000d0: 89c6 4831 c0b0 3b0f 050c 0000 0000 0000  ..H1..;.........
000000e0: 00aa 0041 4100 0000 0005 0000 0000 0000  ...AA...........
000000f0: 0002 0000 0000 0000 0006 0000 0000 0000  ................
00000100: 0003 0000 0000 0000 000a 0000 0000 0000  ................
00000110: 0000 0000 0000 0000 000b 0000 0000 0000  ................
```

Which we submitted for the first flag: `You made it to level 2: thoughtful! You have 64 bytes left to be hand-crafted. This effort is worthy of 1/2 flags. PCTF{th0ugh_wE_have_cl1mBed_far_we_MusT_St1ll_c0ntinue_oNward}`

# Shellcode optimization and removing unneeded dynamic entries (231 bytes)

Since there's a bunch of zeros early on in the ELF, we can store the "/bin/sh" string that our shellcode needs there.
The linker cares about the first stretch of zeros at 0x08-0x0f (it's part of the ELF magic), but it doesn't care about the second stretch from 0x18-0x1f, since that's `e_entry`, and we're not an ordinary executable.
Also, it turns out from trial and error that `DT_STRSZ` and `DT_SYMENT` aren't actually needed either.

## Generator diff
```
65,66c65,67
<     let elf_size = 0x120;
<     let dyn_offset = 0xe0-6-1;
---
>     let binsh_offset = 0x18;
>     let elf_size = 0x101-26;
>     let dyn_offset = 0xe0-26;
137c167,169
<     let shellcode = b"\x48\xba\x2f\x62\x69\x6e\x2f\x73\x68\x00\x48\x83\xe8\x10\x48\x89\x10\x48\x89\xc7\x48\x31\xd2\x48\x83\xe8\x08\x48\x89\x10\x48\x83\xe8\x08\x48\x89\x38\x48\x89\xc6\x48\x31\xc0\xb0\x3b\x0f\x05";
---
>     let shellcode = b"\x2c\x92\x48\x89\xc7\x48\x31\xd2\x2c\x08\x48\x89\x10\x2c\x08\x48\x89\x38\x48\x89\xc6\x48\x31\xc0\xb0\x3b\x0f\x05";
145c177
<         //dynamic::Dyn { d_tag: DT_HASH, d_val: 1 },
---
>         //dynamic::Dyn { d_tag: DT_HASH, d_val: 0xdeadbeefdeadbeef },
147,150c179,182
<         dynamic::Dyn { d_tag: DT_STRTAB, d_val: 2 },
<         dynamic::Dyn { d_tag: DT_SYMTAB, d_val: 3 },
<         dynamic::Dyn { d_tag: DT_STRSZ, d_val: 0 },
<         dynamic::Dyn { d_tag: DT_SYMENT, d_val: 0 },
---
>         dynamic::Dyn { d_tag: DT_STRTAB, d_val: 0 },
>         dynamic::Dyn { d_tag: DT_SYMTAB, d_val: 0 },
>         //dynamic::Dyn { d_tag: DT_STRSZ, d_val: 0 },
>         //dynamic::Dyn { d_tag: DT_SYMENT, d_val: 0 },
158a191,194
>     }
>
>     for (i, x) in b"/bin/sh".iter().enumerate() {
>         elfbytes[binsh_offset+i] = *x;
>     }
```

## Shellcode diff

The shellcode is now no longer self-contained: it depends on being placed relative to the "/bin/sh" string.
Fortunately, the virtual address the shellcode is loaded at is in rax when our `DT_INIT` gets processed, so we can subtract a 1-byte immediate to get our string.
Since our `PT_LOAD` maps the elf as RWX, we can create the argv array by overwriting offsets 0x10-0x18 in the elf header from our shellcode (previously, argv was written relative to the shellcode, which is the same page, so it worked for the same reason).

```
<    0:   48 ba 2f 62 69 6e 2f    movabs $0x68732f6e69622f,%rdx
<    7:   73 68 00
<    a:   48 83 e8 10             sub    $0x10,%rax
<    e:   48 89 10                mov    %rdx,(%rax)
<   11:   48 89 c7                mov    %rax,%rdi
<   14:   48 31 d2                xor    %rdx,%rdx
<   17:   48 83 e8 08             sub    $0x8,%rax
<   1b:   48 89 10                mov    %rdx,(%rax)
<   1e:   48 83 e8 08             sub    $0x8,%rax
<   22:   48 89 38                mov    %rdi,(%rax)
<   25:   48 89 c6                mov    %rax,%rsi
<   28:   48 31 c0                xor    %rax,%rax
<   2b:   b0 3b                   mov    $0x3b,%al
<   2d:   0f 05                   syscall
---
>    0:   2c 92                   sub    $0x92,%al
>    2:   48 89 c7                mov    %rax,%rdi
>    5:   48 31 d2                xor    %rdx,%rdx
>    8:   2c 08                   sub    $0x8,%al
>    a:   48 89 10                mov    %rdx,(%rax)
>    d:   2c 08                   sub    $0x8,%al
>    f:   48 89 38                mov    %rdi,(%rax)
>   12:   48 89 c6                mov    %rax,%rsi
>   15:   48 31 c0                xor    %rax,%rax
>   18:   b0 3b                   mov    $0x3b,%al
>   1a:   0f 05                   syscall
```

## The 231-byte ELF
```
$ xxd ./libgolf2.so
00000000: 7f45 4c46 0201 0100 0000 0000 0000 0000  .ELF............
00000010: 0300 3e00 0100 0000 2f62 696e 2f73 6800  ..>...../bin/sh.
00000020: 4000 0000 0000 0000 0000 0000 0000 0000  @...............
00000030: 0000 0000 4000 3800 0200 4000 0000 0000  ....@.8...@.....
00000040: 0100 0000 0700 0000 0000 0000 0000 0000  ................
00000050: 0000 4141 0000 0000 0000 4141 0000 0000  ..AA......AA....
00000060: e700 0000 0000 0000 e700 0000 0000 0000  ................
00000070: 0010 0000 0000 0000 0200 0000 0700 0000  ................
00000080: 9001 0000 0000 0000 c600 4141 0000 0000  ..........AA....
00000090: 0000 0000 0000 0000 1000 0000 0000 0000  ................
000000a0: 1000 0000 0000 0000 0800 2c92 4889 c748  ..........,.H..H
000000b0: 31d2 2c08 4889 102c 0848 8938 4889 c648  1.,.H..,.H.8H..H
000000c0: 31c0 b03b 0f05 0c00 0000 0000 0000 aa00  1..;............
000000d0: 4141 0000 0000 0500 0000 0000 0000 0000  AA..............
000000e0: 0000 0000 0000 06                        .......
```

# Writing a custom shellcode packer: 224 -> 194 bytes

There's still a bunch of zeros in the ELF before our shellcode. Some of them are important, but not all of them are.
Ideally, we can use contiguous chunks of not-yet-used zeros to allocate fragments of our shellcode, then chain them with 2-byte jumps (`eb xx`).

## The packer

We begin by breaking the shellcode up at it's instruction boundaries, so that we can compute how much we can pack into each fragment of contiguous zeros.
```
    let shellcodes: &[&[u8]] = &[&*b"\x2c\x92", &*b"\x48\x89\xc7", &*b"\x48\x31\xd2", &*b"\x2c\x08", &*b"\x48\x89\x10", &*b"\x2c\x08", &*b"\x48\x89\x38", &*b"\x48\x89\xc6", &*b"\x48\x31\xc0", &*b"\xb0\x3b", &*b"\x0f\x05"];
```

`elf_i` is the currently-considered offset into the ELF, and `sc_i` is the currently considered offset into the list of shellcode instructions.
`actual_shellcode_offset` is written once when the first instruction is allocated, and is used to patch `DT_INIT`.
`prev_jump_disp` is the offset of the `xx` in the most recently written `eb xx`, to be patched when the next instruction is allocated.
`blacklist` is a set of indices that have nonzero values and cause behavioral changes if written to, determined via trial-and-error.

```
    let mut elf_i: usize = shellcode_offset-0x10;
    let mut actual_shellcode_offset = elf_i;
    let mut sc_i: usize = 0;
    let mut prev_jump_disp = None;
    for i in 0x80..0x8a { blacklist.insert(i); }
    for i in 0xa2..0xa4 { blacklist.insert(i); }
    while sc_i < shellcodes.len() {
```
We start by finding a contiguous string of zero-valued non-blacklisted bytes with enough space for at least an instruction.
```
        while elfbytes[elf_i] != 0 || blacklist.contains(&elf_i) { elf_i += 1; }
        let mut zeros_start = elf_i;
        while elfbytes[elf_i] == 0 && !blacklist.contains(&elf_i) && elf_i+1 < elfbytes.len() { elf_i += 1; }
        //  aa 00 00 00 00 bb
        //    ^zs         ^ei
        println!("zeros between {} and {}", zeros_start, elf_i);
        let num_zeros = elf_i - zeros_start;
        if num_zeros < 2 {
            elf_i += 1;
            continue;
        }
```
We then determine how many instructions we can fit into the current gap of zeros, with room for a jump at the end (unless we're already at the last instruction).
```
        let sc_start = sc_i;
        let mut sc_bytes = 0;
        let mut jump_needed = if sc_i != shellcodes.len() { 2 } else { 0 };
        while (sc_bytes + jump_needed < num_zeros) && (sc_i < shellcodes.len()) {
            if sc_bytes + shellcodes[sc_i].len() + jump_needed > num_zeros {
                break
            }
            sc_bytes += shellcodes[sc_i].len();
            sc_i += 1;
            jump_needed = if sc_i != shellcodes.len() { 2 } else { 0 };
        }
        println!("sc bytes {} jump needed {} sc_i {}", sc_bytes, jump_needed, sc_i);
```
If we can fit some instructions in the current gap, we patch up the previous jump, write the bytes, and then write the next jump placeholder.
The `i == 0` check in the middle patches the immediate in `sub immediate, %al` to point to the "/bin/sh" string.
```
        if sc_bytes > 0 {
            if let Some(x) = prev_jump_disp.take() {
                elfbytes[x] = (zeros_start - x - 1) as u8;
            }
            for i in sc_start..sc_i {
                let sc = shellcodes[i];
                elfbytes[zeros_start..zeros_start+sc.len()].copy_from_slice(sc);
                zeros_start += sc.len();
                //  aa 2c 92 00 00 bb
                //          ^zs   ^ei
                if i == 0 {
                    actual_shellcode_offset = zeros_start-2;
                    elfbytes[zeros_start-1] = (zeros_start - binsh_offset - 2) as u8;
                }
            }
            //  aa 2c 92 eb xx bb 00 00
            //                ^ei
            if jump_needed > 0 {
                elfbytes[zeros_start..zeros_start+2].copy_from_slice(b"\xeb\xfe");
                prev_jump_disp = Some(zeros_start+1);
            }
        }
```
## The 224-byte ELF
With this packer we can produce a 224 byte ELF:
```
$ xxd ./libgolf2.so
00000000: 7f45 4c46 0201 0100 0000 0000 0000 0000  .ELF............
00000010: 0300 3e00 0100 0000 2f62 696e 2f73 6800  ..>...../bin/sh.
00000020: 3a00 0000 0000 0000 0000 0000 0000 0000  :...............
00000030: 0000 0000 4000 3800 0200 0100 0000 0700  ....@.8.........
00000040: 0000 0000 0000 0000 0000 0000 4141 0000  ............AA..
00000050: 0000 0000 4141 0000 0000 e000 0000 0000  ....AA..........
00000060: 0000 e000 0000 0000 0000 0010 0000 0000  ................
00000070: 0000 0200 0000 0400 0000 9001 0000 0000  ................
00000080: 0000 bf00 4141 0000 0000 0000 0000 0000  ....AA..........
00000090: 0000 1000 2c7c eb03 0000 1048 89c7 eb04  ....,|.....H....
000000a0: 0000 0800 4831 d22c 0848 8910 2c08 4889  ....H1.,.H..,.H.
000000b0: 3848 89c6 4831 c0b0 3b0f 0500 0000 000c  8H..H1..;.......
000000c0: 0000 0000 0000 0094 0041 4100 0000 0005  .........AA.....
000000d0: 0000 0000 0000 0000 0000 0000 0000 0006  ................
```

Unfortunately, this boundary isn't the next flag boundary, which was kind of a letdown after finally getting the packer to work:
`You made it to level 3: hand-crafted! You have 30 bytes left to be flag-worthy. This effort is worthy of 1/2 flags. PCTF{th0ugh_wE_have_cl1mBed_far_we_MusT_St1ll_c0ntinue_oNward}`
## The 194-byte ELF:

Fortunately, the packer was robust enough that it was just a matter of fiddling with the offsets, zeroing a few more bytes, and tweaking the blacklist to get to the next flag boundary:
### The diff
```
67,68c67,70
<     let elf_size = 0x101-26-6-1;
<     let dyn_offset = 0xe0-26-6-1;
---
>     let elf_size = 0xd1-13-2;
>     let dyn_offset = 0xb0-13-1-2;
85c87
<         e_shentsize: mem::size_of::<SectionHeader>() as _,
---
>         e_shentsize: 0,
96c98
<         p_paddr: 0x41410000,
---
>         p_paddr: 0,
109,111c111,113
<         p_filesz: mem::size_of::<dynamic::Dyn>() as _,
<         p_memsz: mem::size_of::<dynamic::Dyn>() as _,
<         p_align: 8,
---
>         p_filesz: 0,
>         p_memsz: 0,
>         p_align: 0,
223,224c193,194
<     let mut elf_i: usize = shellcode_offset-0x10;
---
>     let mut elf_i: usize = 0x28;
227a198,201
>     for i in 0x34..0x40 { blacklist.insert(i); }
>     for i in 0x44..0x4c { blacklist.insert(i); }
>     for i in 0x50..0x54 { blacklist.insert(i); }
>     for i in 0x63..0x70 { blacklist.insert(i); }
```
### The ELF:
```
$ xxd ./libgolf2.so
00000000: 7f45 4c46 0201 0100 0000 0000 0000 0000  .ELF............
00000010: 0300 3e00 0100 0000 2f62 696e 2f73 6800  ..>...../bin/sh.
00000020: 3a00 0000 0000 0000 2c10 4889 c748 31d2  :.......,.H..H1.
00000030: 2c08 eb20 4000 3800 0200 0100 0000 0700  ,.. @.8.........
00000040: 0000 0000 0000 0000 0000 0000 4141 0000  ............AA..
00000050: 0000 0000 4889 10eb 0200 c22c 0848 8938  ....H......,.H.8
00000060: eb28 c200 0000 0000 0000 0010 0000 0000  .(..............
00000070: 0000 0200 0000 0400 0000 9001 0000 0000  ................
00000080: 0000 a000 4141 0000 0000 4889 c648 31c0  ....AA....H..H1.
00000090: b03b 0f05 0000 0000 0000 0000 0000 0000  .;..............
000000a0: 0500 0000 0000 0000 0c00 0000 0000 0000  ................
000000b0: 0c00 0000 0000 0000 2800 4141 0000 0000  ........(.AA....
000000c0: 0600
```
### The flag:
`You made it to level 4: flag-worthy! You have 1 byte left to be record-breaking. This effort is worthy of 2/2 flags. PCTF{th0ugh_wE_have_cl1mBed_far_we_MusT_St1ll_c0ntinue_oNward} PCTF{t0_get_a_t1ny_elf_we_5tick_1ts_hand5_in_its_ears_rtmlpntyea}`

# The full scripts
Some of the diffs in this post have been truncated for clarity. The full scripts are [in a separate repository](https://github.com/aweinstock314/aweinstock-ctf-writeups/tree/3aa1274c98b49ffe26365365aa1a4d58fc1064e3/plaidctf_2020/golf_so).
