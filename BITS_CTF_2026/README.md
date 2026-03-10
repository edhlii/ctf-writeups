# GCC (Ghost C Compiler)
Có vẻ binary này là một compiler cho mã nguồn C. Thông tin cơ bản:

```bash
$ file ghost_compiler
ghost_compiler: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=d64d20a0400553456624de78cd58afb878a5eb02, for GNU/Linux 3.2.0, stripped
```

Bỏ vô IDA Pro xem có gì.

```c
__int64 __fastcall main(int argc, const char **argv, char **envp)
{
  int i; // [rsp+10h] [rbp-450h]
  unsigned int v5; // [rsp+14h] [rbp-44Ch]
  __int64 v6; // [rsp+18h] [rbp-448h]
  unsigned __int64 v7; // [rsp+20h] [rbp-440h]
  FILE *stream; // [rsp+28h] [rbp-438h]
  __int64 size; // [rsp+30h] [rbp-430h]
  char *ptr; // [rsp+38h] [rbp-428h]
  FILE *s; // [rsp+40h] [rbp-420h]
  char dest[8]; // [rsp+50h] [rbp-410h] BYREF
  __int64 v13; // [rsp+58h] [rbp-408h]
  _BYTE v14[1008]; // [rsp+60h] [rbp-400h] BYREF
  unsigned __int64 v15; // [rsp+458h] [rbp-8h]

  v15 = __readfsqword(0x28u);
  v6 = read_file(*argv, argv, envp);
  if ( v6 == -1 )
    return 1LL;
  v7 = sub_14B5(*argv, v6);
  if ( !v7 )
    return 1LL;
  stream = fopen(*argv, "rb");
  if ( !stream )
    return 1LL;
  fseek(stream, 0LL, 2);
  size = ftell(stream);
  fseek(stream, 0LL, 0);
  ptr = (char *)malloc(size);
  if ( !ptr )
  {
    fclose(stream);
    return 1LL;
  }
  if ( fread(ptr, 1uLL, size, stream) != size )
  {
    free(ptr);
    fclose(stream);
    return 1LL;
  }
  fclose(stream);
  if ( size > v6 + 63 )
  {
    if ( !(unsigned int)sub_1583(ptr, v6, v7) )
    {
LABEL_17:
      free(ptr);
      return 1LL;
    }
    memset(&ptr[v6], 0, 0x40uLL);
  }
  if ( unlink(*argv) )
    goto LABEL_17;
  s = fopen(*argv, "wb");
  if ( !s )
    goto LABEL_17;
  fwrite(ptr, 1uLL, size, s);
  fclose(s);
  free(ptr);
  chmod(*argv, 0x1EDu);
  *(_QWORD *)dest = 543384423LL;
  v13 = 0LL;
  memset(v14, 0, sizeof(v14));
  for ( i = 1; i < argc; ++i )
  {
    strcat(dest, argv[i]);
    *(_WORD *)&dest[strlen(dest)] = 32;
    strcmp(argv[i], "-o");
  }
  v5 = system(dest);
  if ( v5 )
    return v5;
  else
    return 0LL;
}
```

Hàm `sub_1583()` chứa part đầu của flag.

```c
_BOOL8 __fastcall sub_1583(__int64 a1, __int64 a2, __int64 a3)
{
  int i; // [rsp+24h] [rbp-1Ch]
  _BYTE v6[8]; // [rsp+30h] [rbp-10h]
  unsigned __int64 v7; // [rsp+38h] [rbp-8h]

  v7 = __readfsqword(0x28u);
  for ( i = 0; i <= 7; ++i )
  {
    v6[i] = *(_BYTE *)(i + a2 + a1) ^ a3;
    a3 = __ROR8__(a3, 1);
  }
  return v6[0] == 66
      && v6[1] == 73
      && v6[2] == 84
      && v6[3] == 83
      && v6[4] == 67
      && v6[5] == 84
      && v6[6] == 70
      && v6[7] == 123;
}

// Giải mã v6 ra theo từng ký tự ASCII ta được BITSCTF{
```

Hàm `sub_14B5()` đang làm điều gì đó có vẻ khá thú vị.

```c
unsigned __int64 __fastcall sub_14B5(const char *a1, __int64 a2)
{
  int v3; // [rsp+14h] [rbp-1Ch]
  __int64 v4; // [rsp+18h] [rbp-18h]
  __int64 v5; // [rsp+20h] [rbp-10h]
  FILE *stream; // [rsp+28h] [rbp-8h]

  stream = fopen(a1, "rb");
  if ( !stream )
    return 0LL;
  v4 = 0xCBF29CE484222325LL;
  v5 = 0LL;
  while ( 1 )
  {
    v3 = fgetc(stream);
    if ( v3 == -1 )
      break;
    if ( a2 < 0 || v5 < a2 || v5 > a2 + 63 )
    {
      v4 = 0x100000001B3LL * (v4 ^ v3);
      ++v5;
    }
    else
    {
      ++v5;
    }
  }
  fclose(stream);
  return v4 ^ 0xCAFEBABE00000000LL;
}
```

Có thể thấy hàm `main()` thực chất là một wrapper gọi `gcc` để compile mã file code. Hàm này có cơ chế self-modifying. Cơ chế này hoạt động như sau:
- Đọc chính nó vào bộ nhớ: Hàm `fopen(*a2, "rb")` (với *a2 là argv[0]) mở chính file thực thi đang chạy và nạp toàn bộ nội dung vào bộ nhớ (ptr).
- Xóa 64 byte bí mật: Nếu kích thước file đủ lớn, nó gọi `sub_1583` ,là hàm kiểm tra tính hợp lệ của hash v7 với 64 byte tại offset v6. Dùng `memset(&ptr[v6], 0, 0x40uLL);` để xóa trắng (fill null) toàn bộ 64 byte này trong bộ nhớ.
- Tự ghi đè trên đĩa: Nó gọi `unlink(*a2)` để xóa file gốc trên ổ cứng, sau đó tạo file mới, ghi lại nội dung đã bị xóa 64 byte (fwrite), và cấp lại quyền thực thi `chmod(*a2, 0x1EDu)` (0x1ED = 0755 hay rwxr-xr-x).


References: `https://gemini.google.com/u/2/app/390803884166d38f?hl=vi&pageId=none`