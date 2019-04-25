---
title: Google CTF Quals 2017 - Food
authors: Toshi Piazza
date: 2017-06-26
categories: reverse-engineering 
---

This writeup is for the "Food" challenge found in Google CTF Quals 2017, from the
reversing category. This writeup and others were also submitted to the Google CTF Writeup
Competition.

## JNI-Native Reversing

We are only given a `food.apk`, and from there we immediately unzip it and run `dex2jar`,
followed by `jd-gui` to view the source code. Fortunately, the source is very succinct:

[gist:id=45b06c676233b3a512bbf95f4675aed5]

Although I'm not well versed in Android development, it looks like it's loading a library
`libcook.so` from either one of `lib/{armeabi,x86}`. We turn our attention to the arm
library, and symbolize it using a script we found [here](https://github.com/trojancyborg/IDA_JNI_Rename). This resolves
certain awkward indirect function calls that otherwise would appear as unnamed constant
offsets into the JNI struct (e.g. `JNI_FindClass`).

The bizarre disassembly in `JNI_Onload` seems to indicate that all useful strings have
been encrypted, and are only decrypted at runtime. One such example of this is shown
below:

![`decrypt_string`]({filename}/assets/IDA_encrypt.png)

Note that `decrypt_string` here, as we learn later is a variadic function with the
following signature: `char *decrypt_string(int a1, ...)`. We implement the
`decrypt_string` function in python so that we can determine all the strings used by the
application:

[gist:id=2ff3316926ce979af6406c1a1cd98d09]

We can now resolve many important strings which are passed as arguments to `fopen` and
`fwrite`, shown below, as well as to later JNI runtime functions.

[gist:id=16519167f0c1808a93763631d373e73f]

Unfortunately, binwalk doesn't recognize dex files, but clearly we're writing an embedded
dex file to the location `/data/data/com.google.ctf.food/files/d.dex`, which we can dump
from the binary with IDA.

Before we analyze this dex file, we continue reversing the `JNI_Onload` routine, to
discover a particularly scary routine which parses `/proc/self/maps` and patches itself at
runtime, a little later on.

[gist:id=991a8b39f2c0453391a475c4814a136d]

At a high level, it reads `/proc/self/maps` until it finds the base address of `/d.dex`,
and looks for the magic header, `dex\n0`. It then proceeds to patch the JVM bytecode at
runtime with a sinister binary string of length 0x90 that's xor'd with 0x5a. This `d.dex`,
we presume is the same `d.dex` file we dumped from earlier.

We go to offset 0x720 of the `d.dex` file, to discover what appears to be 0x90 bytes of
jvm-bytecode nops. We patch in the unxor'd content into the dex file using IDA r2, and
decompile it in much the same way we did with classes.dex.

## Reversing `d.dex`

Unfortunately the files were a bit large, but we note the following routines in F.java:

[gist:id=55ef7ec232eeb918ab625ab9304b07e4]

In the unpatched `d.dex`, `cc()` was originally nopped to thwart static analysis. S.java
sets up a view in which one can request foods in a particular order, by pressing the
corresponding buttons. `onRecieve()` will take the indices of each order and save it in
`this.k`, and once all 8 have been entered `cc()` xors `k` with `arrayOfBytes`, and
compares it to a new string.

Once we've figured out the right `k`, we will be given the flag. We can figure out this
`k` with the following python code:

[gist:id=4465d74dd4b359f4753cbb9a94d93e90]

To save some time, we can construct a simple `Soln.java` class, and simply import
`com.google.ctf.food.ℝ` (since we couldn't get any of this to run in an android emulator).

[gist:id=fcf093f1836950276389f44b2b96ac48]

This spits out the flag, `CTF{bacon_lettuce_tomato_lobster_soul}`
