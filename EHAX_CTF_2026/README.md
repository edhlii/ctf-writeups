---
title: EHAX CTF 2026 Writeup

---

# EHAX CTF 2026 Writeup

Giải này mình vô muộn, làm trong một buổi sáng nên đc mỗi một bài.

## I guess bro
Bỏ vô DiE xem trước.

![image](https://hackmd.io/_uploads/SJnKvQWtbl.png)

Challenge này chạy không được. Lý do vì nó được compile bằng kiến trúc [RISC](https://vi.wikipedia.org/wiki/RISC). Kiến trúc này sử dụng tập lệnh khác với kiến trúc máy tính phổ thông hiện đại CISC. Thật ra muốn chạy thì có thể cài máy ảo, nhưng trước tiên mình thử phân tích tĩnh xem có gì hay đã.

Lúc đầu mình thử decompile với IDA Pro nhưng không khả thi lắm.

Dùng Ghidra decompile thử. Trace theo string thì đến một nơi có vẻ giống hàm main. Đổi tên các hàm nhìn cho nó dễ.

```c=
undefined8 main(void)
{
  long lVar1;
  undefined8 uVar2;
  undefined1 auStack_90 [128];
  
  print_banner();
  FUN_0001085c();
  lVar1 = FUN_00014f24(auStack_90,0x80,PTR_DAT_0007e588);
  if (lVar1 == 0) {
    puts("Input error!");
    uVar2 = 1;
  }
  else {
    lVar1 = FUN_0001ed44(auStack_90,"\n");
    auStack_90[lVar1] = 0;
    lVar1 = FUN_0001ee70(auStack_90);
    if (lVar1 == 0x23) {
      lVar1 = FUN_00010732(auStack_90);
      if (lVar1 == 0) {
        puts(&DAT_00051440);
        uVar2 = 1;
      }
      else {
        puts(&DAT_00051410);
        printf("Flag: %s\n",auStack_90);
        uVar2 = 0;
      }
    }
    else {
      puts("Wrong length! Keep guessing...");
      uVar2 = 1;
    }
  }
  return uVar2;
}
```

Ok ngon luôn, dễ thấy ta cần quan tâm tới hàm `FUN_00010732`. Đây sẽ là hàm check xem key có chuẩn không.

```c=

undefined8 FUN_00010732(undefined8 param_1)

{
  long lVar1;
  long lVar2;
  undefined8 uVar3;
  int iStack_28;
  
  lVar1 = strcmp("EH4X{n0t_th3_r34l_fl4g}");
  if (lVar1 == 0) {
    puts("Nice try, but that\'s not it!");
    return 0;
  }
  lVar1 = strcmp(param_1,"EH4X{try_h4rd3r_buddy}");
  if (lVar1 == 0) {
    puts("Getting warmer... but nope!");
    return 0;
  }
  lVar1 = FUN_0002022e();
  iStack_28 = 0;
  do {
    iStack_28 = iStack_28 + 1;
  } while (iStack_28 < 100000);
  lVar2 = FUN_0002022e();
  if (lVar2 - lVar1 < 0xc351) {
    lVar1 = FUN_000105cc(param_1);
    if ((lVar1 != 0) && (lVar1 = FUN_00010622(param_1), lVar1 != 0)) {
      uVar3 = FUN_00010700(param_1);
      return uVar3;
    }
  }
  else {
    puts("Debugger detected! Exiting...");
    FUN_000110c0(1);
  }
  return 0;
}
```

Chưa gì là thấy 2 cái fake flag =)).

Logic chính để cook cái flag nằm ở hàm `FUN_000105cc`.

```c=

undefined8 FUN_000105cc(byte *param_1) {
  byte bVar1;
  byte *pbVar2;
  byte *pbVar3;
  byte bVar4;
  byte *pbVar5;
  byte local_28 [35];
  byte abStack_5 [5];
  
  pbVar2 = local_28;
  pbVar5 = &DAT_00057bc8;
  bVar4 = 0;
  pbVar3 = pbVar2;
  do {
    bVar1 = *pbVar5;
    pbVar5 = pbVar5 + 1;
    *pbVar3 = bVar1 ^ bVar4 ^ 0xa5;
    bVar4 = bVar4 + 7;
    pbVar3 = pbVar3 + 1;
  } while (pbVar5 != &UNK_00057beb);
  do {
    bVar4 = *pbVar2;
    bVar1 = *param_1;
    pbVar2 = pbVar2 + 1;
    param_1 = param_1 + 1;
    if (bVar4 != bVar1) {
      return 0;
    }
  } while (pbVar2 != abStack_5);
  return 1;
}
```

Hàm này đang thực hiện việc sau:
- Khởi tạo biến counter `bVar4 = 0`, string `pbVar3` rỗng, `pbVar5` là lưu giá trị của một biến toàn cục nào đó (lát nữa dump được). Sau đó thực hiện lặp qua `pbVar5`.
    - Gọi vị trí hiện tại là `i`, thực hiện gán `pbVar[i] = pbVar5[i] ^ bVar4 ^ 0xa5`.
    - Thực hiện `bVar4 += 7`.
- So sánh `param_1` với `pbVar3` vừa mới cook ra. Nếu 2 string bằng nhau thì return 1.

Mình viết lại mã giả C cho nó dễ đọc. Cái này là nháp thôi nên không đúng syntax đâu, để cho dễ hình dung cái hàm.
```c=
int FUN_000105cc(char* param){
    char *res;
    char *s = &DAT_00057bc8;
    int cnt = 0;
    do{
        res[i] = s[i] ^ cnt ^ 0xa5;
        cnt += 7;
        ++i;
    } while(i < s.size());
    return param_1 == res;
}
```

Ok tới đây bảo A.I gen cái script để decrypt cái flag. `DAT_00057bc8` thì có sẵn rồi chỉ cần dump ra rồi copy/paste vào thôi.

```py=
def decrypt_flag(encrypted_bytes):
    flag = ""
    counter = 0  # bVar4 khởi tạo bằng 0
    key = 0xA5   # Hằng số XOR trong code

    for b in encrypted_bytes:
        # Logic: *pbVar3 = bVar1 ^ bVar4 ^ 0xa5;
        decrypted_char = b ^ counter ^ key
        flag += chr(decrypted_char)

        # Logic: bVar4 = bVar4 + 7;
        counter = (counter + 7) & 0xFF  # Giữ trong phạm vi 1 byte (0-255)

    return flag


encrypted_data = [
    0xE0, 0xEA, 0x9F, 0xE8, 0xC2, 0xFF, 0xBF, 0xE1, 0xC2, 0xFD, 0x96, 0xDB, 0x82, 0x8D, 0xF4, 0xA8,
    0x8A, 0xA6, 0xB3, 0x14, 0x5D, 0x69, 0x4D, 0x35, 0x7E, 0x69, 0x4C, 0x7B, 0x13, 0x5A, 0x14, 0x17,
    0x28, 0x71, 0x36, 0x00, 0x00, 0x00, 0x00, 0x00
]

if not encrypted_data:
    print("LOI: Ban chua nhap du lieu hex tu Ghidra vao script!")
    print("Test cong thuc voi ky tu dau tien (gia dinh):")
    print(f"Neu byte hex la 0xE0 -> Giai ma ra: {chr(0xE0 ^ 0 ^ 0xA5)}")
else:
    print("Flag tim duoc la:")
    print(decrypt_flag(encrypted_data))
```

Kết quả chạy script.
```bash
$ python exploit.py
Flag tim duoc la:
EH4X{y0u_gu3ss3d_th4t_r1sc_cr4ckm3}PY¦¯´
```

Flag: `EH4X{y0u_gu3ss3d_th4t_r1sc_cr4ckm3}`

## pathfinder
Thói quen bỏ vào DiE trước.

![image](https://hackmd.io/_uploads/SyrzSV-FWl.png)

Vào Ghidra phân tích tĩnh thử. Hàm main khá đơn giản.

```c=

undefined8 main(void)

{
  long lVar1;
  int iVar2;
  ssize_t sVar3;
  undefined8 uVar4;
  size_t sVar5;
  long in_FS_OFFSET;
  char local_158 [64];
  char local_118 [264];
  
  lVar1 = *(long *)(in_FS_OFFSET + 0x28);
  FUN_001015a1();
  printf("Are you a pathfinder?\n[y/n]: ");
  fflush(stdout);
  sVar3 = read(0,local_158,1);
  if ((int)sVar3 == 0) {
    puts("No input?");
    fflush(stdout);
    uVar4 = 1;
  }
  else {
    do {
      iVar2 = getchar();
    } while (iVar2 != 10);
    if (local_158[0] == 'n') {
      puts("Understandable. See you again, maybe..");
      fflush(stdout);
      uVar4 = 1;
    }
    else if (local_158[0] == 'y') {
      printf("Ok, tell me the best path: ");
      fflush(stdout);
      memset(local_158,0,0x40);
      sVar3 = read(0,local_158,0x40);
      if ((int)sVar3 == 0) {
        puts("Where dat path tho?");
        fflush(stdout);
        uVar4 = 1;
      }
      else {
        sVar5 = strcspn(local_158,"\n");
        local_158[sVar5] = '\0';
        iVar2 = FUN_00101444(local_158);
        if (iVar2 == 0) {
          puts("Better luck next time.");
          fflush(stdout);
          uVar4 = 1;
        }
        else {
          FUN_00101602(local_158,local_118);
          printf("You have what it takes. Flag: %s\nBye.\n",local_118);
          fflush(stdout);
          uVar4 = 0;
        }
      }
    }
    else {
      puts("Invalid option");
      fflush(stdout);
      uVar4 = 1;
    }
  }
  if (lVar1 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return uVar4;
}
```

Trước tiên mình chú ý đến hàm `FUN_00101444` vì nó đang thực hiện logic check. Tiện tay đổi tên hàm thành `check_wrapper` cho dễ nhìn.

Mình để A.I đọc code cho nhanh. Từ code này ta biết được đây là dạng giải mê cung, lần đầu mình làm dạng này.

Mình thêm một struct để định nghĩa lại `DAT_555555558120` cho dễ nhìn. Đồng thời đổi tên biến này thành `MOVES_LIST` luôn.

![image](https://hackmd.io/_uploads/BypoWvft-l.png)

```c=

bool check_wrapper(char *s)

{
  undefined1 uVar1;
  MoveInfo *pMVar2;
  byte bVar3;
  byte bVar4;
  uint offset_x;
  uint offset_y;
  int iVar5;
  bool bVar6;
  uint x_pos;
  uint y_pos;
  char *s_cpy;
  int local_14;
  int iStack_10;
  byte local_c;
  byte bStack_b;
  char cStack_a;
  char cur;
  undefined4 dx;
  undefined4 dy;
  undefined1 magic_1;
  undefined1 magic_2;
  
  x_pos = 0;
  y_pos = 0;
  s_cpy = s;
  while( true ) {
    if (*s_cpy == '\0') {
      if ((x_pos == 9) && (y_pos == 9)) {
        iVar5 = FUN_55555555526b(s);
        bVar6 = iVar5 == -0x7945adf4;
      }
      else {
        bVar6 = false;
      }
      return bVar6;
    }
    cur = *s_cpy;
    dx = MOVES_LIST[(int)(uint)(byte)cur].dx;
    dy = MOVES_LIST[(int)(uint)(byte)cur].dy;
    pMVar2 = MOVES_LIST + (int)(uint)(byte)cur;
    magic_1 = pMVar2->magic_1;
    magic_2 = pMVar2->magic_2;
    uVar1 = pMVar2->check_flag;
    if (uVar1 == '\0') break;
    offset_x = x_pos + dx;
    offset_y = y_pos + dy;
    if ((9 < offset_x) || (9 < offset_y)) {
      return false;
    }
    bVar3 = FUN_55555555523f(x_pos,y_pos);
    bVar4 = FUN_55555555523f(offset_x,offset_y);
    if ((bVar4 & (cur * 'k' ^ magic_2 ^ 0x3cU)) == 0 && (bVar3 & (cur * 'k' ^ magic_1 ^ 0x3cU)) ==  0
       ) {
      return false;
    }
    s_cpy = s_cpy + 1;
    x_pos = offset_x;
    y_pos = offset_y;
  }
  return false;
}

undefined1 FUN_55555555523f(int param_1,int param_2)
{
  return (&DAT_5555555580a0)[param_2 + param_1 * 10];
}
```

Đầu tiên chương trình khởi tạo 2 biến `x_pos, y_pos` đều bằng 0, là điểm xuất phát. Sau đó nhảy vào vòng lặp và thực hiện kiểm tra flag.

Mình phát hiện `MOVES_LIST` được khởi tạo trong hàm `_INIT_2`. Hàm này chạy trước khi gọi vào `main`. Kiểm tra xem.

```c=

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void _INIT_2(void)

{
  memset(MOVES_LIST,0,0xc00);
  MOVES_LIST[0x4e].dx = -1;
  MOVES_LIST[0x4e].dy = 0;
  MOVES_LIST[0x4e].magic_1 = 0xa2;
  MOVES_LIST[0x4e].magic_2 = 0xa7;
  MOVES_LIST[0x4e].check_flag = 1;
  MOVES_LIST[0x53].dx = 1;
  MOVES_LIST[0x53].dy = 0;
  MOVES_LIST[0x53].magic_1 = 0x8c;
  MOVES_LIST[0x53].magic_2 = 0x89;
  MOVES_LIST[0x53].check_flag = 1;
  MOVES_LIST[0x45].dx = 0;
  MOVES_LIST[0x45].dy = 1;
  MOVES_LIST[0x45].magic_1 = 0xe9;
  MOVES_LIST[0x45].magic_2 = 0xe3;
  MOVES_LIST[0x45].check_flag = 1;
  MOVES_LIST[0x57].dx = 0;
  MOVES_LIST[0x57].dy = -1;
  MOVES_LIST[0x57].magic_1 = 0x69;
  MOVES_LIST[0x57].magic_2 = 99;
  MOVES_LIST[0x57].check_flag = 1;
  MOVES_LIST[0x6e].dx = 1;
  MOVES_LIST[0x6e].dy = 0;
  MOVES_LIST[0x6e].magic_1 = 0x11;
  MOVES_LIST[0x6e].magic_2 = 0x22;
  MOVES_LIST[0x6e].check_flag = 0;
  MOVES_LIST[0x73].dx = -1;
  MOVES_LIST[0x73].dy = 0;
  MOVES_LIST[0x73].magic_1 = 0x33;
  MOVES_LIST[0x73].magic_2 = 0x44;
  MOVES_LIST[0x73].check_flag = 0;
  MOVES_LIST[0x65].dx = 0;
  MOVES_LIST[0x65].dy = -1;
  MOVES_LIST[0x65].magic_1 = 0x55;
  MOVES_LIST[0x65].magic_2 = 0x66;
  MOVES_LIST[0x65].check_flag = 0;
  MOVES_LIST[0x77].dx = 0;
  MOVES_LIST[0x77].dy = 1;
  MOVES_LIST[0x77].magic_1 = 0x77;
  MOVES_LIST[0x77].magic_2 = 0x88;
  MOVES_LIST[0x77].check_flag = 0;
  _DAT_555555558d20 = 1;
  return;
}
```

Ok, như vậy hàm này đang gán giá trị cho `MOVES_LIST` ở các vị trí `0x4e, 0x53, 0x45, 0x57, 0x6e, 0x73, 0x65, 0x77`. Tương ứng với các giá trị trong bảng mã ASCII là `N, S, E, W, n, s, e, w`. Có vẻ ám chỉ các hướng di chuyển trong mê cung.

Ngoài ra ta cần biết thông tin về mảng `DAT_5555555580a0`. Xref đến thì thấy nó được khởi tạo ở `_INIT_1`.

```c=
void _INIT_1(void)
{
  byte bVar1;
  byte bVar2;
  int local_14;
  
  for (local_14 = 0; local_14 < 100; local_14 = local_14 + 1) {
    bVar1 = (&DAT_555555556020)[local_14];
    bVar2 = FUN_5555555551c9(local_14);
    (&DAT_5555555580a0)[local_14] = bVar1 ^ bVar2;
  }
  return;
}

uint FUN_5555555551c9(int param_1)
{
  return param_1 << 3 ^ param_1 * 0x1f + 0x11U ^ 0xffffffa5;
}
```

Rất may mắn mảng `DAT_555555556020` khi xref tới thì đã có giá trị sẵn nên không cần mò nữa:

```py   
DAT_555555556020 = [
    0xBC, 0x97, 0xF6, 0xD3, 0x08, 0x21, 0x5E, 0x77, 0xEC, 0xC5, 0xB2, 0x9B, 0x45, 0x69, 0x16, 0x37, 
    0x2E, 0x07, 0x06, 0x63, 0x78, 0x91, 0xAD, 0xC7, 0x9C, 0x70, 0x42, 0x2B, 0x35, 0xD9, 0xEE, 0x85, 
    0x5E, 0xB7, 0x90, 0xF2, 0xE8, 0x01, 0x3B, 0x57, 0x09, 0xE5, 0xD2, 0xBB, 0xA0, 0x49, 0x7E, 0x15, 
    0xC5, 0x2D, 0x2F, 0x03, 0x54, 0x7B, 0x82, 0xA7, 0xB9, 0x95, 0x62, 0x4B, 0x15, 0x39, 0xC3, 0xEF, 
    0x71, 0x5D, 0xBF, 0x93, 0xC8, 0xE1, 0x1B, 0x37, 0x2D, 0x05, 0xF1, 0xD1, 0x89, 0xA9, 0x5E, 0x73, 
    0xE1, 0xCD, 0xCA, 0x23, 0x38, 0x51, 0x6E, 0x87, 0xD9, 0xB0, 0x81, 0x61, 0x7A, 0x13, 0x2C, 0xC5, 
    0x1E, 0x77, 0x5B, 0xB0
]
```

Ok, với các thông tin trên thì mình  viết script giải. Đầu tiên mình tái tạo lại mê cung theo đúng logic chương trình. Sau đó dùng BFS để tìm đường đi tới đích. Bảo AI viết cho nhanh.

```py=
import struct
from collections import deque

raw_dat_6020 = [
    0xBC, 0x97, 0xF6, 0xD3, 0x08, 0x21, 0x5E, 0x77, 0xEC, 0xC5, 0xB2, 0x9B, 0x45, 0x69, 0x16, 0x37,
    0x2E, 0x07, 0x06, 0x63, 0x78, 0x91, 0xAD, 0xC7, 0x9C, 0x70, 0x42, 0x2B, 0x35, 0xD9, 0xEE, 0x85,
    0x5E, 0xB7, 0x90, 0xF2, 0xE8, 0x01, 0x3B, 0x57, 0x09, 0xE5, 0xD2, 0xBB, 0xA0, 0x49, 0x7E, 0x15,
    0xC5, 0x2D, 0x2F, 0x03, 0x54, 0x7B, 0x82, 0xA7, 0xB9, 0x95, 0x62, 0x4B, 0x15, 0x39, 0xC3, 0xEF,
    0x71, 0x5D, 0xBF, 0x93, 0xC8, 0xE1, 0x1B, 0x37, 0x2D, 0x05, 0xF1, 0xD1, 0x89, 0xA9, 0x5E, 0x73,
    0xE1, 0xCD, 0xCA, 0x23, 0x38, 0x51, 0x6E, 0x87, 0xD9, 0xB0, 0x81, 0x61, 0x7A, 0x13, 0x2C, 0xC5,
    0x1E, 0x77, 0x5B, 0xB0
]

def fun_1c9(param_1):
    term1 = (param_1 << 3) & 0xFFFFFFFF
    term2 = ((param_1 * 0x1f) + 0x11) & 0xFFFFFFFF
    term3 = 0xffffffa5

    return (term1 ^ term2 ^ term3) & 0xFFFFFFFF


def init_grid():
    final_grid = [0] * 100
    for i in range(100):
        bVar1 = raw_dat_6020[i]
        bVar2 = fun_1c9(i) & 0xFF  # Lấy byte thấp nhất vì gán vào mảng byte
        final_grid[i] = bVar1 ^ bVar2
    return final_grid


def get_grid_val(grid, x, y):
    idx = y + x * 10
    if 0 <= idx < 100:
        return grid[idx]
    return 0

class Move:
    def __init__(self, char, dx, dy, magic1, magic2):
        self.char = char
        self.dx = dx
        self.dy = dy
        self.magic1 = magic1
        self.magic2 = magic2


moves_config = [
    Move('N', -1, 0, 0xa2, 0xa7),  # 0x4e
    Move('S',  1, 0, 0x8c, 0x89),  # 0x53
    Move('E',  0, 1, 0xe9, 0xe3),  # 0x45
    Move('W',  0, -1, 0x69, 0x63)  # 0x57 (99 decimal = 0x63)
]


def solve_maze():
    grid = init_grid()
    queue = deque([(0, 0, "")])
    visited = set([(0, 0)])

    solutions = []

    print(f"[*] Bắt đầu giải mê cung từ (0,0) đến (9,9)...")

    while queue:
        cx, cy, path = queue.popleft()
        if cx == 9 and cy == 9:
            solutions.append(path)
            continue  # Tiếp tục tìm đường khác nếu có

        cur_val = get_grid_val(grid, cx, cy)

        for m in moves_config:
            nx = cx + m.dx
            ny = cy + m.dy
            if not (0 <= nx <= 9 and 0 <= ny <= 9):
                continue
            k_const = 107
            cur_char_val = ord(m.char)

            mask_current = (cur_char_val * k_const) ^ m.magic1 ^ 0x3c
            mask_next = (cur_char_val * k_const) ^ m.magic2 ^ 0x3c

            mask_current &= 0xFF
            mask_next &= 0xFF

            next_val = get_grid_val(grid, nx, ny)

            cond1 = (next_val & mask_next) != 0
            cond2 = (cur_val & mask_current) != 0

            if cond1 or cond2:
                if (nx, ny) not in visited:
                    visited.add((nx, ny))
                    queue.append((nx, ny, path + m.char))

    return solutions


if __name__ == "__main__":
    if raw_dat_6020[0] == 0 and raw_dat_6020[1] == 0:
        print("[!] CẢNH BÁO: Bạn chưa điền dữ liệu vào mảng 'raw_dat_6020'.")
        print("    Vui lòng điền 100 bytes hex vào đầu script.")
    else:
        found_paths = solve_maze()

        if found_paths:
            print(f"[+] Tìm thấy {len(found_paths)} đường đi:")
            for p in found_paths:
                print(f"Path: {p}")
                print(f"Length: {len(p)}")
        else:
            print(
                "[-] Không tìm thấy đường đi nào hợp lệ. Hãy kiểm tra lại raw_dat_6020.")
```

Kết quả chạy.

```bash 
$ ./pathfinder
Are you a pathfinder?
[y/n]: y
Ok, tell me the best path: EESSSWWSSSSSSEEEEEEEENNESS
You have what it takes. Flag: EHAX{2E3S2W6S8E2NE2S}
Bye.
```

Flag: `EHAX{2E3S2W6S8E2NE2S}`