---
title: Tamu CTF 2026 Writeup

---

# Tamu CTF 2026 Writeup

## nucleus

![image](https://hackmd.io/_uploads/B15eCHiqZe.png)

`nucleus21.exe` khi chạy sinh ra file `nucleus22.exe`.

Mở IDA lên phân tích.

Luồng hoạt động chương trình khá đơn giản:
- Copy nội dung của chương trình hiện tại.
- XOR toàn bộ với một ký tự do user nhập.
- Lưu vào `.rsrc` và đẻ ra file mới mang theo xác của file cũ.

Nhiệm vụ bây giờ là tìm về thế hệ đầu tiên xem các ký tự đã được dùng làm key để XOR là gì.

Vì dữ liệu được giấu bên trong mỗi file chính là một file thực thi Windows (PE File) của thế hệ trước đó, mà mọi PE File luôn luôn bắt đầu bằng 2 byte Magic Number là MZ (Mã ASCII: 0x4D và 0x5A).

=> `Khoá = Byte_đầu_resource ^ 0x4D`

Tạo một script python tự động hoá việc này.

```python=
import pefile
import os

def extract_and_decrypt(start_filename):
    flag = ""
    current_file = start_filename
    
    print(f"[*] Bắt đầu giải mã từ mẫu vật: {current_file}\n" + "-"*40)

    while True:
        try:
            # Parse file PE
            pe = pefile.PE(current_file)
        except Exception as e:
            print(f"[-] Không thể đọc {current_file} dưới dạng PE. Có thể đã đến lõi cuối cùng. Lỗi: {e}")
            break

        resource_data = None
        
        # Duyệt tìm Resource Type 10 (RT_RCDATA) và ID 101 (0x65)
        if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
            for rsrc_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                if rsrc_type.struct.Id == 10:  # RT_RCDATA
                    for rsrc_id in rsrc_type.directory.entries:
                        if rsrc_id.struct.Id == 101:  # ID 101 (0x65)
                            # Trích xuất dữ liệu thô (Raw Data)
                            rsrc_lang = rsrc_id.directory.entries[0]
                            data_rva = rsrc_lang.data.struct.OffsetToData
                            size = rsrc_lang.data.struct.Size
                            resource_data = pe.get_data(data_rva, size)
                            break
        
        if not resource_data:
            print("[*] Không tìm thấy Resource ID 101 nữa. Đã bóc hết các lớp!")
            break

        # Khai thác lỗ hổng Known-Plaintext: PE file luôn bắt đầu bằng 'M' (0x4D)
        # Khóa = Byte_đầu_tiên_của_Resource ^ 0x4D
        key = resource_data[0] ^ 0x4D
        char_key = chr(key)
        flag += char_key
        
        print(f"[+] {current_file}: Tìm thấy Resource. Khóa XOR là '{char_key}' (0x{key:02X})")

        # Giải mã toàn bộ khối dữ liệu bằng khóa vừa tìm được
        decrypted_data = bytearray(len(resource_data))
        for i in range(len(resource_data)):
            decrypted_data[i] = resource_data[i] ^ key

        # Tạo tên file cho thế hệ tiếp theo (ví dụ: nucleus21.exe -> nucleus_gen20.exe)
        next_file = f"nucleus_gen{len(flag)}.exe" 
        
        # Ghi file giải mã ra đĩa để tiếp tục vòng lặp
        with open(next_file, "wb") as f:
            f.write(decrypted_data)
            
        current_file = next_file

    # Xử lý và in kết quả cuối cùng
    print("-" * 40)
    print(f"[!!!] Quá trình lột xác hoàn tất!")
    print(f"[!!!] Chuỗi khóa thu được (theo thứ tự lột): {flag}")
    
    # Tuỳ thuộc vào việc malware được tạo ra từ trong ra ngoài hay ngoài vào trong,
    # Flag có thể bị ngược. Chúng ta in ra cả 2 chiều cho chắc ăn.
    print(f"[!!!] Flag có thể là: {flag}")
    print(f"[!!!] Hoặc đảo ngược: {flag[::-1]}")

if __name__ == "__main__":
    # Điền tên file ban đầu của bạn vào đây
    extract_and_decrypt("nucleus21.exe")
```

![image](https://hackmd.io/_uploads/B1XkmUjcZx.png)

Flag: `gigem{RCD4Ta_i5_N3aT}`.

## challenge7

Bài này thuộc dạng VM, mình không có nhiều kinh nghiệm với dạng bài này. Sau giải mình đọc writeup của người khác và làm lại.

![image](https://hackmd.io/_uploads/HyzbonOjZx.png)

Mở IDA Pro để phân tích tĩnh.

Chương trình đang lấy tiến trình của chính nó qua `proc/self/exe`.

```c=
  memset(v62, 0, sizeof(v62));
  f = fopen("/proc/self/exe", "rb");
  if ( !f )
    goto LOAD_FILE_FAILED;
  v4 = f;
  if ( fread(&input, 1uLL, 0x40uLL, f) != 64 )
    goto FAILED;
  if ( input != 'FLE\x7F' )
    goto FAILED;
  if ( v69 != 2 )
    goto FAILED;
  v7 = off;
  if ( !off )
    goto FAILED;
```
