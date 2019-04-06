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

```java
public class FoodActivity extends AppCompatActivity {
    public static Activity activity;
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView((int) R.layout.activity_food);
        activity = this;
        System.loadLibrary("cook");
    }
}
```

Although I'm not well versed in Android development, it looks like it's loading a library
`libcook.so` from either one of `lib/{armeabi,x86}`. We turn our attention to the arm
library, and symbolize it using a script we found [here](https://github.com/trojancyborg/IDA_JNI_Rename). This resolves
certain awkward indirect function calls that otherwise would appear as unnamed constant
offsets into the JNI struct (e.g. `JNI_FindClass`).

The bizarre disassembly in `JNI_Onload` seems to indicate that all useful strings have
been encrypted, and are only decrypted at runtime. One such example of this is shown
below:

![`decrypt_string`]({{ site.baseurl }}/assets/IDA_encrypt.png)

Note that `decrypt_string` here, as we learn later is a variadic function with the
following signature: `char *decrypt_string(int a1, ...)`. We implement the
`decrypt_string` function in python so that we can determine all the strings used by the
application:

```python
def decrypt_string(sz, nums):
    ret = [ None ] * (2 * sz)
    for i in range(sz):
        from ctypes import c_uint
        v5 = nums[i]
        byte_1 = c_uint( v5 & 0x000000ff         ).value
        byte_2 = c_uint((v5 & 0x0000ff00) >> 0x08).value
        byte_3 = c_uint((v5 & 0x00ff0000) >> 0x10).value
        byte_4 = c_uint((v5 & 0xff000000) >> 0x18).value
        ret[i*2+0] = ~((~byte_1 | byte_2) & (~byte_2 | v5))
        ret[i*2+1] = byte_4 ^ byte_3
    from ctypes import c_byte
    return "".join(map(lambda x: chr(c_byte(x).value), ret))
```

We can now resolve many important strings which are passed as arguments to `fopen` and
`fwrite`, shown below, as well as to later JNI runtime functions.

```c
FILE *fp = fopen("/data/data/com.google.ctf.food/files/d.dex", "wb");
if (fp != NULL) {
    fwrite("dex\n035...", 0x15A8, 1, fp);
    fclose(fp);
}
```

Unfortunately, binwalk doesn't recognize dex files, but clearly we're writing an embedded
dex file to the location `/data/data/com.google.ctf.food/files/d.dex`, which we can dump
from the binary with IDA.

Before we analyze this dex file, we continue reversing the `JNI_Onload` routine, to
discover a particularly scary routine which parses `/proc/self/maps` and patches itself at
runtime, a little later on.

```c
FILE *fp = fopen("/proc/self/maps", "r");
while (fgets(s, 256, fp)) {
    if (strstr(s, "/d.dex")) {
        int page_size = sysconf(_SC_PAGE_SIZE);
        char *dex = strtoul(s, 0, 16);
        if (mprotect(dex, (1968 / page_size + 8) * page_sz,
                     PROT_READ|PROT_WRITE|PROT_EXEC))
            return 0;
        for (char *i = dex; i < dex + 8 * page_sz; ++i) {
            if (strcmp(i, "dex\n0") == 0) {
                for (int i = 0; i < 0x90; ++i)
                    dex[0x720 + i] = xor_me[i] ^ 0x5a;
            }
        }
        break;
    }
}
```

At a high level, it reads `/proc/self/maps` until it finds the base address of `/d.dex`,
and looks for the magic header, `dex\n0`. It then proceeds to patch the JVM bytecode at
runtime with a sinister binary string of length 0x90 that's xor'd with 0x5a. This `d.dex`,
we presume is the same `d.dex` file we dumped from earlier.

We go to offset 0x720 of the `d.dex` file, to discover what appears to be 0x90 bytes of
jvm-bytecode nops. We patch in the unxor'd content into the dex file using IDA r2, and
decompile it in much the same way we did with classes.dex.

## Reversing `d.dex`

Unfortunately the files were a bit large, but we note the following routines in F.java:

```java
public void cc() {
    byte[] arrayOfByte = new byte[8]
        { 26, 27, 30, 4, 21, 2, 18, 7 };
    for (int i = 0; i < 8; i++)
        arrayOfByte[i] = ((byte)(arrayOfByte[i] ^ this.k[i]));
    if (new String(arrayOfByte).compareTo(
            "\023\021\023\003\004\003\001\005") == 0)
        Toast.makeText(this.a.getApplicationContext(),
                       new String(ℝ.ℂ(flag, this.k)), 1).show();
}

public void onReceive(Context paramContext, Intent paramIntent) {
    // ...
    this.k[this.c] = ((byte)i);
    cc();
    // reset this.k if this.cc++ == 8
}
```

In the unpatched `d.dex`, `cc()` was originally nopped to thwart static analysis. S.java
sets up a view in which one can request foods in a particular order, by pressing the
corresponding buttons. `onRecieve()` will take the indices of each order and save it in
`this.k`, and once all 8 have been entered `cc()` xors `k` with `arrayOfBytes`, and
compares it to a new string.

Once we've figured out the right `k`, we will be given the flag. We can figure out this
`k` with the following python code:

```python
bytes = [ 26, 27, 30, 4, 21, 2, 18, 7 ]
targt = [023, 021, 023, 003, 004, 003, 001, 005, ]
k = map(lambda (i,j): i ^ j, zip(bytes, targt))
```

To save some time, we can construct a simple `Soln.java` class, and simply import
`com.google.ctf.food.ℝ` (since we couldn't get any of this to run in an android emulator).

```java
import com.google.ctf.food.ℝ;

public class soln {
    private static byte[] flag = {
        -19, 116, 58, 108, -1, 33, 9, 61, -61,
        -37, 108, -123, 3, 35, 97, -10, -15,
        15, -85, -66, -31, -65, 17, 79, 31,
        25, -39, 95, 93, 1, -110, -103, -118,
        -38, -57, -58, -51, -79 };
    private static byte[] k = {
        9, 10, 13, 7, 17, 1, 19, 2 };

    public static void main(String []args) {
        System.out.println(new String(ℝ.ℂ(flag, k)));
    }
}
```

This spits out the flag, `CTF{bacon_lettuce_tomato_lobster_soul}`
