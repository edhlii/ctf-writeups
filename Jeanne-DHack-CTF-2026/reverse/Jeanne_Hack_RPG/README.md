# Level 1
Yêu cầu:  

![alt text](image.png)

Một số thông tin tổng quan:  

![alt text](image-1.png)  

![alt text](image-2.png) 

Theo hint thì ta không cần quan tâm tới file `jdhack-rpg`. Tôi cũng đã thử decompile nó bằng Ghidra nhưng không có gì thú vị.  

Decompile `level_1.so` với Ghidra. Việc đầu tiên là check xem có chuỗi `JDHACK` trong đó không. Và rất may là có:  

![alt text](image-3.png)  

Chuỗi này được gọi ở hàm `enter_village(char*)`:  

```c

void enter_village(char *param_1) {
  // ... 
  snprintf(local_408,0x400,"Congratulations! You can validate with\nJDHACK{%s}",param_1);
  window_msg(local_408);
  return;
}
```  

Hàm `enter_village()` này sẽ in ra nội dung full của flag, ta cần tìm xem chuỗi `param_1` là gì. Xem cross-reference, ta biết được hàm `enter_village()` này được gọi ở hàm `keep_moving_forward()`.  

![alt text](image-4.png)

```c

void keep_moving_forward(void) {
  // ...
    if (local_c == 0x30) {
      window_clear();
      sus_str = (char *)window_prompt("What is the secret code: ");
      pcVar4 = strdup(sus_str);
      pcVar4 = (char *)enc(pcVar4);
      iVar1 = strcmp("B1ofs@urX1t4tswhwDeM2w2m1od",pcVar4);
      if (iVar1 == 0) {
        choices_dispose(uVar2);
        free(pcVar4);
        enter_village(sus_str);
        return;
      }
      choices_dispose(uVar2);
      free(pcVar4);
      attack_by_wolves(2);
      return;
    }
    if ((local_c == 0x1b) || (local_c == 0x71)) break;
    window_msg("I did not understand what you are saying");
  }
  choices_dispose(uVar2);
  return;
}
```  

Hàm này thực hiện những việc sau:
- Nhập vào `sus_str` (biến này đã được tôi đổi tên). `pcVar4` copy giá trị của xâu `sus_str`.
- Mã hoá xâu `pcVar4` qua hàm `enc()`.
- So sánh xâu `pcVar4` đã mã hoá với xâu `B1ofs@urX1t4tswhwDeM2w2m1od`. Nếu 2 xâu bằng nhau thì gọi hàm `enter_village(sus_str)`.

Như vậy ta cần kiểm tra hàm `enc()` mã hoá xâu thế nào, từ đó đảo ngược mã hoá xâu `B1ofs@urX1t4tswhwDeM2w2m1od` để lấy được xâu `sus_str` chính xác.  

Rất may mắn là hàm `enc()` mã hoá khá đơn giản.  

![alt text](image-6.png)  

```c
byte * enc(byte *param_1) {
  byte *i;
  for (i = param_1; *i != 0; i = i + 1) {
    *i = *i ^ 1;
  }
  return param_1;
}
```  

Logic hàm `enc()` là duyệt qua từng ký tự trong xâu `param_1` (hay chính là xâu `sus_str`). Sau đó XOR từng ký tự đó với `1`.  

Để đảo ngược ta chỉ cần XOR từng ký tự trong xâu kết quả với `1` là xong. Tôi viết một python script để tự động hoá việc này.

```py
def decrypt(encoded_data):
    # Nếu đầu vào là chuỗi, chuyển thành bytearray để có thể chỉnh sửa
    if isinstance(encoded_data, str):
        data = bytearray(encoded_data, "utf-8")
    else:
        data = bytearray(encoded_data)

    # Duyệt qua từng byte và thực hiện XOR 1 (giống hệt hàm enc)
    for i in range(len(data)):
        data[i] = data[i] ^ 1

    return data

encoded_bytes = (
    b"B1ofs@urX1t4tswhwDeM2w2m1od"  
)

decrypted_data = decrypt(encoded_bytes)

print(f"Dữ liệu sau khi giải mã: {decrypted_data.decode('utf-8')}")
```  

![alt text](image-7.png)  

Flag: `JDHACK{C0ngrAtsY0u5urvivEdL3v3l0ne}`  

# Level 2

Yêu cầu:  

![alt text](image-8.png)  

Một số thông tin cơ bản:  

![alt text](image-9.png)  

![alt text](image-10.png)  

Challenge này có file bị `strip`, nên việc reverse sẽ hơi khó khăn. Lại kịch bản cũ, ta tìm xem có xâu `JDHACK` không. Rất may mắn là lại có =)). Xâu này được gọi ở hàm `sus_func()` (đã đổi tên).

![alt text](image-12.png)  



