---
title: NorthSec 2018 MarsAnalytica
authors: Toshi Piazza
date: 2018-05-24
categories: reverse-engineering 
---

This is (yet another) posthumous writeup from NorthSec, on the MarsAnalytica challenge. It
features a heavily (rop)fuscated binary which accepts a 19-character pin; if the pin is
correct, it produces a flag, and otherwise prints an access denied message.

Unfortunately, running angr on the challenge doesn't work in a reasonable amount of time;
I instead opt to guide angr to the solution by stopping at the first symbolic branch:

```py
p = angr.Project("./MarsAnalytica")
s = p.factory.entry_state(add_options=angr.options.unicorn)
sm = p.factory.simulation_manager(s)
sm.step(until=lambda lpg: len(lpg.active) > 1)
```

This code should stop at the first logical "check" of our input, and after 10 minutes or
so the step function exits, and drops us into a repl:

```
$ python -i soln.py
>>>> sm
<SimulationManager with 2 active>
>>>> list(sm.active[1].guards)[-1]
<Bool 0x0#56 .. file_/dev/stdin_24_1_789_8[31;0] >s 0x20>
```

Here we see there are two active paths, the second of which has a path predicate that
constrains a byte of our input to a value > 0x20. This is just an ascii check! Since the
second active path is clearly the one we want, we can easily drop the first one and
continue:

```py
sm.drop(stash='active', filter_func=lambda s: s != sm.active[1])
sm.step(until=lambda lpg: len(lpg.active) > 1)
```

As we continue we see similar ascii checks for 0x20 and 0x7f on each byte of stdin.  There
are going to be 38 of these, and it would be tedious to comb through all of these by hand;
we can blow past these by revising our script:

```py
def constrain_stdin(st):
    for _ in xrange(19):
        k = st.posix.files[0].read_from(1)
        st.solver.add(k > 0x20)
        st.solver.add(k < 0x7f)
    st.posix.files[0].seek(0)
    st.posix.files[0].length = 19
p = angr.Project("./MarsAnalytica")
s = p.factory.entry_state(add_options=angr.options.unicorn)
constrain_stdin(s)
sm = p.factory.simulation_manager(s)
sm.step(until=lambda lpg: len(lpg.active) > 1)
```

Now, when we run angr once again we no longer stop at any of these ascii constraints since
there's only one sat branch for all of these conditions. Our next constraint looks
something like the following:

```
$ python -i soln.py
>>>> sm
<SimulationManager with 2 active>
>>>> list(sm.active[0].guards)[-1]
<Bool 0x3fcf == __mul__(0x0#24 .. file_/dev/stdin_24_6_6_8, 0x0#24 ..  file_/dev/stdin_24_e_14_8, ((0x0#24 .. file_/dev/stdin_24_c_12_8 + (0xffffffff * 0x0#24 ..  file_/dev/stdin_24_a_10_8)) ^ 0x0#24 .. file_/dev/stdin_24_d_13_8))>
```

This looks much more interesting to us, and likely constitutes some constraints on our
pin. We can hazard a guess and say that we want to get *more* constrained as opposed to
*less* constrained, and take the first active branch. Continuing along, we notice a trend
that the first active branch is always the branch which enforces the equality path
constraint.  We use this to our advantage to write a final automation script:

```py
def constrain_stdin(st):
    for _ in xrange(19):
        k = st.posix.files[0].read_from(1)
        st.solver.add(k > 0x20)
        st.solver.add(k < 0x7f)
    st.posix.files[0].seek(0)
    st.posix.files[0].length = 19
p = angr.Project("./MarsAnalytica")
s = p.factory.entry_state(add_options=angr.options.unicorn)
constrain_stdin(s)
sm = p.factory.simulation_manager(s)

sm.step(until=lambda lpg: len(lpg.active) > 1)
while len(sm.deadended) == 0:
    sm.drop(stash='active', filter_func=lambda s: s != sm.active[0])
    print sm.one_active.state.posix.dumps(0)
    sm.step(until=lambda lpg: len(lpg.deadended) > 1 or len(lpg.active) > 1)
## output:
## @@@@@@!@@@G@}?7@@@@
## @}@@@@!!@@G@}?7?@@0
## 7}@@@w!!@]G@}?7?B(0
## 7}@1@w!!@]G&}?7?B(0
## 7}=1@w!!~]G&}?7?B(0
## 7@R1!w!0p]G&}?7aB("
## y?5}'q!a_),rrO7xgM{
## a>C|(@!\hB@qp5cpK1y
## {5O{*rc>z&(plA!`@&D
## +%>c9`cuth@Xk(7u`Fv
## e^?t6Yc>v-/iS'7p?%?
## {?@X+cc>h55MyA!s^DY
## q4Eo-eyMq-1dd0-leKx
```

This yields us a pin: `q4Eo-eyMq-1dd0-leKx`; we can verify it works by simply
running the binary:

```
  __  __                                      _       _   _
 |  \/  |                   /\               | |     | | (_)
 | \  / | __ _ _ __ ___    /  \   _ __   __ _| |_   _| |_ _  ___ __ _
 | |\/| |/ _` | '__/ __|  / /\ \ | '_ \ / _` | | | | | __| |/ __/ _` |
 | |  | | (_| | |  \__ \ / ____ \| | | | (_| | | |_| | |_| | (_| (_| |
 |_|  |_|\__,_|_|  |___//_/    \_\_| |_|\__,_|_|\__, |\__|_|\___\__,_|
                                                 __/ |
                                                |___/        NSEC 2018


Citizen Access ID: q4Eo-eyMq-1dd0-leKx

[+] ACCESS GRANTED!

**  FLAG-l0rdoFb1Nq4EoeyMq1dd0leKx  **

[-] Session Terminated
```

### Food for Thought

Initially I was hoping for a solution which employed Triton. Since it sports an associated
pintool I assumed it would be a lot faster to run and to pick up path constraints. The
technique of dumping the path predicate and solving for one particular branch was also
inspired by Triton's concolic execution.

Furthermore, Triton was used in a partial [solution][tigress] to the Tigress VM
Challenges, another set of challenges which demonstrates virtualization obfuscation
techniques. Unfortunately, I couldn't get Triton to run on this binary but I'd love to see
someone reconstruct the source using this same technique!

[tigress]: https://github.com/jonathansalwan/Tigress_protection
