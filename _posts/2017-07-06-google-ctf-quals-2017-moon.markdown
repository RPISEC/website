---
title: Google CTF Quals 2017 - Moon
date: 2017-07-06
categories: reverse-engineering 
---

This writeup is for the reversing challenge "Moon" we solved during 2017 Google CTF Quals.

## Dealing with GLEW

A big problem we noticed early on was the use of GL3W, which generates code to lazily load
all OpenGL functions at runtime--at all places where an OpenGL function was used we would
simply see a call to some offset in the data section.  We can see the huge routine which
calls LoadLibrary on every OpenGL function, at address `0x4032c0`.

Instead of symbolizing (by hand) all of the symbols, we only bothered to load ones which
had valid XREFs to them, saving a bit of time.

## Running the Program

Unfortunately all the RPI-sold computers from our year are not yet reported to support
OpenGL 4.3, so first and foremost we had to patch the OpenGL verification check from 4.3
to 4.2. Surprisingly, this "just worked" despite the code making use of Compute Shaders
which I had thought to be introduced in OpenGL 4.3.

The program simply opens up a window, and asks for a password. After we've entered 32
characters, the program either responds "good" (presumably), or "Nope".

![Running the program]({{ site.baseurl }}/assets/moon.png)

When we XREF the string Nope, we see that it is used when constructing the texture to be
printed for this SDL event loop iteration. Not too far from "Nope" do we find "Good", and
we notice that "Good" is only selected if a particular global variable is set. We trace
this back to the following code in main:

```c
if ( Size != size || Size && memcmp(Memory, Buf2, Size) )
  should_compute = 1;
else
  should_compute = 2;
```

We want `should_compute` here to be 2, meaning the memcmp succeeded. `Buf2` is the
following string:

```
30c7ead97107775969be4ba00cf5578f1048ab1375113631dbb6871dbe35162b1
c62e982eb6a7512f3274743fb2e55c818912779ef7a34169a838666ff3994bb4d
3c6e14ba2d732f14414f2c1cb5d3844935aebbbe3fb206343a004e18a092daba0
2e3c0969871548ed2c372eb68d1af41152cb3b61f300e3c1a8246108010d282e1
6df8ae7bff6cb6314d4ad38b5f9779ef23208efe3e1b699700429eae1fa93c036
e5dcbe87d32be1ecfac2452ddfdc704a00ea24fbc2161b7824a968e9da1db7567
12be3e7b3d3420c8f33c37dba42072a941d799ba2eebbf86191cb59aa49a80ebe
0b61a79741888cb62341259f62848aad44df2b809383e09437928980f
```
So, once our input is hashed, it must match the above value. The hashing of our input
seems to occur at address `0x401BF0`, and through windbg we can confirm that our input is
the first argument, and the hash is written out to the second argument. Nothing much
happens here, however, though we do see references to `glUseProgram` and
`glDispatchCompute`, as seen below:

```c
glUseProgram(glComputeProgram);
// ...
buffer = glMapBuffer(37074, 35002);
// ... buffer initialization
glUnmapBuffer(37074, v10);
glDispatchCompute(8, 8, 1);
GLint fence = glFenceSync(37143, 0);
if ( (glClientWaitSync(fence, 1, 1000000000) - 37147)
        & 0xFFFFFFFD )
{
    glMemoryBarrier(0xFFFFFFFF);
    glDeleteSync(v20);
    buffer = (char *)glMapBuffer(37074, 35002);
    // ... save the hashed password out to the main function
    glUnmapBuffer(37074, buffer);
    glUseProgram(0);
}
```

Although we can see the fragment and vertex shaders in clear view in the strings, we can't
see any reference to the compute shader glsl source. We assume it's encrypted somehow, so
we break on `glCompileShader` and wait until the glsl compute shader is decrypted. This is
a wild guess, as the shader could have been precompiled somehow but we punt on this.

The dumped source is as follows, after adding the proper formatting:

```glsl
#version 430
layout(local_size_x=8,local_size_y=8) in;
layout(std430,binding=0) buffer shaderExchangeProtocol{
    uint state[64];
    uint hash[64];
    uint password[32];
};
vec3 calc(uint p) {
    float r = radians(p);
    float c = cos(r);
    float s = sin(r);
    // rotation matrix
    mat3 m  = mat3(  c, -s,0.0,
                     s,  c,0.0,
                   0.0,0.0,1.0);
    vec3 pt = vec3(1024.0,0.0,0.0);
    vec3 res= m*pt;
    res+=vec3(2048.0,2048.0,0.0);
    return res;
}
uint extend(uint e) {
    uint i;
    uint r=e^0x5f208c26;
    for (i=15;i<31;i+=3) {
        uint f=e<<i;
        r^=f;
    }
    return r;
}
uint hash_alpha(uint p) {
    vec3 res=calc(p);
    return extend(uint(res[0]));
}
uint hash_beta(uint p) {
    vec3 res=calc(p);
    return extend(uint(res[1]));
}
void main() {
    uint idx = gl_GlobalInvocationID.x +
               gl_GlobalInvocationID.y * 8;
    uint final;
    if (state[idx] != 1) {
        return;
    }
    if ((idx&1)==0) {
        final=hash_alpha(password[idx/2]);
    } else {
        final=hash_beta(password[idx/2]);
    }
    uint i;
    for (i=0;i<32;i+=6) {
        final ^= idx << i;
    }
    uint h=0x5a;
    for (i=0;i<32;i++){
        uint p=password[i];
        uint r=(i*3)&7;
        p=(p<<r)|(p>>(8-r));
        p&=0xff;
        h^=p;
    }
    final^=(h|(h<<8)|(h<<16)|(h<<24));
    hash[idx]=final;
    state[idx]=2;
    memoryBarrierShared();
}
```

## Reversing the Compute Shader

We note a few properties of the hashing function below:

1. The $h$ variable is constant for all iterations of this compute shader. It is dependent
   only on the password.
2. The only place in which the index, $idx$ affects $final$ is where we compute `final
   ^= idx << i` in a loop. This is completely reversible.
3. Other than these 2 conditions, $final$ is completely dependent on the current character.

Our goal here is to exploit these characteristics to find an idx-independent and
password-independent hash for each character. This would allow us to brute force the
password character by character. We can find the h of the real password like so:

$$
\begin{align*}
    hash_C  &= reverse\_idx(final\_C) \oplus hash_h \\
    hash_C' &= reverse\_idx(final\_C) \oplus hash_h'
\end{align*}
$$

Here, $hash_C$ is the value of the first index corresponding to the 'C' character in 'CTF'
(we're assuming the password starts thus because of the flag format), for the real
password, or the password we'd like to find. $hash_C'$ is the value of the same index in
our dummy string, say the string:

`CTF{AAAAAAAAAAAAAAAAAAAAAAAAAAAA`

which also has a 'C' at the same index.  $hash_h$ represents the $h$ value used to xor
with the output of the hash function for the real password, and likewise $hash_h'$ is this
value of h for our dummy password.

Note that $final_C$ is the same for both the real and the dummy password; it's passed out
of the hash function. The $reverse\_idx$ function removes $final_C$'s dependence on idx,
reproduced below:

$$
\begin{align*}
reverse\_idx(final,idx) = final &\oplus (idx<<0)  \\
                                &\oplus (idx<<6)  \\
                                &\oplus \dots     \\
                                &\oplus (idx<<26)
\end{align*}
$$

Finally, to compute $hash_h$, we simply need to perform the following:

$$
hash_h = hash_C' \oplus hash_C ⊕ hash_h'
$$

Although it took a lot of work, we now have h of the target password, since we know
$hash_C'$, $hash_C$, and $hash_h'$. With this, we can figure out the hash value of
every character in the password, independent of the character's index, and brute force
them character by character.

## Brute Forcing the Password

Unfortunately we were unable to replicate this algorithm forwards in C++, for some unknown
reasons (probably something to do with the `calc` function). Since we were running out of
time, we opted instead to compute a lexicon of characters up front with the debugger. We
then took the hash of each character and made them idx-independent, as well as un-xor'd
their h terms, like so:

```python
def xor_position(ret, idx):
    from ctypes import c_uint
    for i in range(0, 32, 6):
        ret ^= (idx << i)
    return c_uint(ret).value

lexicon = { }
def add_to_lexicon(alpha, chars, h):
    alpha = [ int(alpha[i:i+8], 16) for i in range(0, 512, 16) ]
    idx = 0
    assert len(alpha) == len(chars)
    for i,j in zip(chars, alpha):
        # idx * 2 since we only care about even-numbered idx's
        lexicon[xor_position(j ^ h, idx*2)] = i
        idx += 1
alpha1 = "<hash for ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef here>"
add_to_lexicon(alpha1, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef", 0x7a7a7a7a)
alpha2 = "<hash for ghijklmnopqrstuvwxyz_1234567890- here>"
add_to_lexicon(alpha2, "ghijklmnopqrstuvwxyz_1234567890-", 0x93939393)
```

Now, all we need to do is take `Buf2`'s characters and render them also idx-independent,
un-xor them with the known h for this password (which turns out to be `0x6f6f6f6f`,
computed in the previous section) and then match each hash with the known values in our
lexicon, as below:

```python
Buf2 = "<hash for Buf2 here, shown above>"
Buf2 = [ int(Buf2[i:i+8], 16) for i in range(0, 512, 16) ]
idx = 0
for i in Buf2:
    print lexicon[xor_position(i ^ 0x6f6f6f6f, idx*2)]
    idx += 1
# NOTE: our lexicon originally didn't have "{}" so this will throw
# an exception as is...
```

The resulting flag is: `CTF{OpenGLMoonMoonG0esT0TheMoon}`
