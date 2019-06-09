---
title: Plaid CTF 2018 - Plaid Adventures
authors: Toshi Piazza
date: 2018-05-08
categories: reverse-engineering
---

This was a (reasonably) fun challenge from Plaid CTF this year, and one of the only
reversing challenges I got to do. Unfortunately we solved this challenge *posthumously*,
and only solved it after we were given a hint on IRC after the CTF had ended.

> It is pitch black.  
>   
> You are likely to be eaten by a grue.  
>   
> Hint: "You can find the yellow orb in the maze."

First things first, the program files comprised a web-based interface for a MUD-type game.
The game is surprisingly simple; we need to:

1. Collect 4 colored orbs
2. Collect the silver key
3. Unlock a door
4. Insert the 4 orbs into a statue

Afterwards we can touch each orb; after 48 tries a message pops up:o

```
The orbs darken for a second. It seems like the code wasn't accepted.
```

Looks like we need to touch the orbs in a certain order in order to get the flag.

## Analysis

Digging through the program files, we notice a `Plaid Adventure.gblorb` file, which is of
a known file format to `file`:

```
$ file Release/Plaid\ Adventure.gblorb 
Release/Plaid Adventure.gblorb: IFF data, Blorb Interactive Fiction with executable chunk
```

This is a well-known file format which contains bytecode commonly used for implementing
games; the bytecode is for the glulx virtual machine. A decompiler for this file format
can be found [here](https://github.com/wertercatt/mrifk).

The important bits we decompiled and subsequently cleaned up are shown below:

```
[ routine53995 local0 ;
  ...
    if (routine146071(10,local0,269) == 1) {
        TouchSphere(465371-->counter,0);
    }
    if (routine146071(10,local0,269) == 2) {
        TouchSphere(465371-->counter,1);
    }
    if (routine146071(10,local0,269) == 3) {
        TouchSphere(465371-->counter,2);
    }
    if (routine146071(10,local0,269) == 4) {
        TouchSphere(465371-->counter,3);
    }
    465371-->counter = 465371-->counter + 1;
    if (465371-->counter == 48) {
        if (CheckSpheres() == 1) {
            ...
            PrintFlag();
            ...
        } else {
            ...
        }
    }
    ...
    return 0;
];

[ TouchSphere cnt orb local8 local16 ;
    local8 = cnt % 3 * 2;
    @shiftl 1 local8 -> local16;
    ORB_INPUT[cnt/3] = ORB_INPUT[cnt/3] | (orb * local16);
    return 1;
];

[ CheckSpheres local0 local4 local8 ;
    for (local0 = 0; local0 < 16; ++local0)
        ORB_COPY[local0] = ORB_INPUT[local0];
    for (local0 = 0; local0 < 8; ++local0) {
        for (local4 = 0; local4 < 16; ++local4) {
            ORB_CHECK[local4] = 0;
            for (local8 = 0; local8 < 16; ++local8)
                ORB_CHECK[local4] = ORB_CHECK[local4] + ORB_INPUT[local8] * 478802[local4 * 16 + local8];
        }
        for (local4 = 0; local4 < 16; ++local4)
            ORB_INPUT[local4] = 478546[ORB_CHECK[local4]];
    }
    for (local0 = 0; local0 < 16; ++local0) {
        if (ORB_INPUT[local0] ~= ORB_FINAL[local0])
            return 0;
    }
    return 1;
];
```

Here we can clearly see the orb-touching logic, as well as the call to the `CheckSpheres`
function which gets triggered on the 48th try, as expected. The `TouchSpheres` function is
interesting since it populates the `ORB_INPUT` array which has a length of 16. Every three
orb touches are condensed into a single byte in this array and each orb touch takes up 2
bits, so we can only input numbers into this array of up to value `0b00111111 = 63`.

At this point we should also reverse the `CheckSpheres` function. The first part saves
`ORB_INPUT` to `ORB_COPY`, to be used later when printing the flag. Next, we perform 8
rounds of a dot product between `ORB_CHECK` and `478802`, a 256-byte array, followed by an
easily reversible scramble of `ORB_CHECK` over `478546`, another 256-byte array. Finally,
it checks this transformed `ORB_INPUT` against some `ORB_FINAL` hash.

We can recover these arrays in the console from the javascript console:

```js
function dump(addr, len) {
    var ret = [ ];
    for (var i = 0; i < len; ++i) {
        ret.push(Quixe.ReadByte(addr + i));
    }
    return ret;
}
dump(ORB_FINAL, 16);
dump(478802, 256);
dump(478546, 256);
```

Now, we can proceed to reverse this function using sage:

```python
arr_478546 = [   ...   ]
arr_478802 = [ [ ... ] ]
A = Matrix(IntegerModRing(256), arr_478802).transpose()
x = [ 87,195,64,120,241,182,73,155,184,230,203,64,220,61,157,133 ] # ORB_FINAL...
for _ in range(8):
    b = vector(map(arr_478546.index, x))
    x = b * A.inverse()
print x
```

Unfortunately, this yields the array `(188, 185, 130, 28, 247, 150, 58, 227, 106, 0, 116,
197, 113, 25, 178, 70)`, which we can't physically input by the game; recall that all
values in the original function *must* be less than 64. At this point we're lost since we
can't quite find any more solutions with this method...

## Hidden Command

Finally, after the CTF ended, a hint was released on IRC that mentioned a hidden `xyzzy`
command which would alter the `ORB_FINAL` array slightly. After running this command and
subsequently dumping the value of `ORB_FINAL`, we notice that it changed a single byte of
this final hash:

```
[ 87,195,64,120,241,182,73,155,184,230,203,64,220,61,157,134 ]
```

Thus we update the script accordingly, hoping that it yields a matrix that we are
physically able to create within the game:

```python
arr_478546 = \
[  69, 174, 190, 198, 155,  80, 118, 246,  79, 130, 242, 102, 172, 201, 207,  98,
   70,  64,  42, 253,  72, 173, 108, 238, 163, 134, 223,  77, 226,  66, 100, 248,
   28,  87, 224,   8, 125,  26, 154, 230,  94, 200, 145, 164, 222,  57,  35, 219,
  245,  71, 218, 168, 205, 112, 175, 115, 122, 128,  61,  47, 191,  81,  49,  76,
  133,  22,  24, 251, 183, 227, 105,  91,  39,  59,  33,   6,  29, 167, 162,  10,
   56, 214, 101, 193, 186,  78, 254, 255,  68, 129,  84, 132, 228, 206, 215,  20,
  106, 170,  95, 202,  17,   3, 212,  82,   7, 114, 107, 182, 165,  16, 233, 225,
   12,  99, 247, 197, 199, 235,  46, 104,   5, 231,   4, 146,  55, 113, 204, 184,
  147, 236,   1,  63,  53,  13, 124, 243, 244,  30, 203,  50,  11, 150, 176, 144,
   97,  41, 237, 177, 188,  74, 217, 239, 160,  44, 156,  54,  52,  88, 187, 131,
  211, 229, 194,  83, 178, 157, 121,   9,  14,  21,  37,  43,   2,   0, 232, 143,
  213,  89, 208, 166, 196, 136, 123, 181, 159,  23, 158,  51, 103, 117 ,216 ,179,
   90,  40,  19, 169, 209,  67,  73,  48, 139, 141, 110,  58, 120,  45, 140, 171,
   75,  96,  86,  15,  62,  36, 240,  27,  34, 138, 250,  85, 249,  25, 111, 119,
  195, 221,  93, 149, 234, 137, 180, 127,  32, 189, 151,  92, 153, 126, 185, 210,
  252, 148, 142,  65,  18, 135, 241,  31, 152, 116, 220, 161, 192, 109,  38,  60]
arr_478802 = \
[[119, 238,  11,  62, 170,  98, 117, 174, 149,  84,  21, 189, 160,  11, 144, 101],
 [140,  40, 180, 211,  60,  90, 150, 101,  80, 115, 147, 172, 200, 154, 213, 240],
 [194, 130, 244,  75,  44, 171, 121, 162, 124, 244, 187, 221,  51, 236, 247, 241],
 [ 62, 135,  15,  14, 153, 157,  55, 128,   6, 218, 238,  40,  98, 114, 245, 193],
 [118,  19, 241, 209,  83, 222,  46, 183,  15, 185,   1,  60, 216,  58, 179, 125],
 [ 42, 194, 189, 107, 132, 202, 203, 139, 130, 254,  60,   3, 167, 156, 203,  93],
 [ 40, 113,  89, 132,  68,  31, 215, 174, 142, 110,  15,  77,  67, 165, 158,   7],
 [ 54, 236, 133,  22,  36, 118,  96, 211,  28, 210,  72,  59,  43, 251, 164, 160],
 [164, 177,  68, 251, 222,  64, 245, 161, 178, 231, 124,  78, 232, 167,  31, 234],
 [212, 215,  70,  88, 248,  61, 225, 183, 150, 207, 125, 210, 208,  47,  87, 156],
 [ 82,  22,   7, 205, 201, 229, 146, 198,  58,   4,  81, 245, 168, 186, 211, 133],
 [ 57, 145, 244,  79, 120, 176,  40,  53,  43, 161, 175, 200, 205, 213, 170, 190],
 [253,  34,  58,  57, 252,  20, 222,  30, 138, 206, 146,   3,  25,  18, 163, 205],
 [ 26, 230,  40, 178,   9, 230, 167, 158, 156, 105, 194,  55, 244, 154,  43,  66],
 [ 80, 244,  84,  34,  29,  64,  76,  26, 247, 176,  33, 148,  65, 249, 194,  98],
 [184, 122,  42, 221,  50, 119, 247,  33, 113,  10, 236, 107,  66, 224,  39,  37]]
A = Matrix(IntegerModRing(256), arr_478802).transpose()
x = [87,195,64,120,241,182,73,155,184,230,203,64,220,61,157,134]
for _ in range(8):
    b = vector(map(arr_478546.index, x))
    x = b * A.inverse()
def get_colors(final):
    ret = ""
    for i in final:
        ret += bin(i)[2:].rjust(6, "0")[::-1]
    def chunks(l, n):
        for i in range(0, len(l), n):
            yield l[i:i+n]
    op2color = [ "blue", "green", "red", "yellow" ]
    for i in chunks(ret, 2):
        print(op2color[int(i,2)])
get_colors(x)
```

Luckily, all the resulting matrix entries are under 64, so this script gives us a sequence
of orbs to touch, which yields the flag `PCTF{Tw1styL1ttl3Fl4g}`.
