import unicodedata
from typing import Literal

ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

def _normalize_key(keyword: str, alphabet: str = ALPHABET):
    """Chuẩn hoá khóa thành danh sách offset số theo `alphabet`.

    Hàm nội bộ: lọc các ký tự không thuộc `alphabet`, chuyển về chữ hoa,
    rồi ánh xạ sang vị trí 0..len(alphabet)-1.

    Args:
        keyword: Chuỗi khóa đầu vào (có thể chứa ký tự ngoài alphabet).
        alphabet: Bảng chữ cái sử dụng (mặc định A–Z).

    Returns:
        List[int]: Danh sách offset (mỗi phần tử ∈ [0, len(alphabet))).

    Raises:
        ValueError: Nếu sau khi lọc không còn ký tự hợp lệ nào trong `keyword`.
    """
    vals = [alphabet.index(c.upper()) for c in keyword if c.upper() in alphabet]
    if not vals:
        raise ValueError("Khóa phải chứa ít nhất một chữ cái trong alphabet.")
    return vals

def vigenere_autokey_encrypt(
    plaintext: str,
    keyword: str,
    alphabet: str = ALPHABET,
    keep_nonalpha: bool = True,
    mode: Literal['plaintext', 'ciphertext'] = "plaintext",  # "plaintext" hoặc "ciphertext"
) -> str:
    """Mã hoá bằng Vigenère Autokey.

    Autokey xây keystream bằng cách nối `keyword` với chính dữ liệu:
    - `mode="plaintext"`: keystream = keyword + plaintext (chuẩn, phổ biến).
    - `mode="ciphertext"`: keystream = keyword + ciphertext.

    Với ký tự không thuộc `alphabet`:
    - Nếu `keep_nonalpha=True` (mặc định): giữ nguyên và KHÔNG tiêu thụ keystream.
    - Nếu `keep_nonalpha=False`: bỏ qua khỏi kết quả (cũng không tiêu thụ keystream).

    Args:
        plaintext: Bản rõ cần mã hoá.
        keyword: Khóa ban đầu (ít nhất một ký tự thuộc `alphabet`).
        alphabet: Bảng chữ cái (mặc định 26 chữ cái A–Z).
        keep_nonalpha: Có giữ nguyên ký tự ngoài alphabet hay không.
        mode: Kiểu autokey, "plaintext" hoặc "ciphertext".

    Returns:
        Chuỗi đã mã hoá (giữ nguyên hoa/thường theo từng ký tự gốc).

    Raises:
        ValueError: Nếu `keyword` không có ký tự hợp lệ trong `alphabet`,
                    hoặc `mode` không thuộc {"plaintext", "ciphertext"}.
    """
    ks = _normalize_key(keyword, alphabet)
    keystream = list(ks)
    out: list[str] = []
    for ch in plaintext:
        up = ch.upper()
        if up in alphabet:
            k = keystream.pop(0) if keystream else 0
            p = alphabet.index(up)
            c_idx = (p + k) % len(alphabet)
            c = alphabet[c_idx]

            # Autokey: nối plaintext hoặc ciphertext vào keystream
            if mode == "plaintext":
                keystream.append(p)
            elif mode == "ciphertext":
                keystream.append(c_idx)

            out.append(c if ch.isupper() else c.lower())
        else:
            out.append(ch if keep_nonalpha else "")
    return "".join(out)

def vigenere_autokey_decrypt(
    ciphertext: str,
    keyword: str,
    alphabet: str = ALPHABET,
    keep_nonalpha: bool = True,
    mode: Literal['plaintext', 'ciphertext'] = "plaintext",  # "plaintext" hoặc "ciphertext"
) -> str:
    """Giải mã Vigenère Autokey.

    Khác biệt quan trọng: khi `mode="plaintext"`, keystream trong khi giải mã
    được mở rộng bằng **plaintext vừa khôi phục**; khi `mode="ciphertext"`,
    keystream mở rộng bằng chính **ciphertext**.

    Với ký tự không thuộc `alphabet`:
    - Nếu `keep_nonalpha=True` (mặc định): giữ nguyên và KHÔNG tiêu thụ keystream.
    - Nếu `keep_nonalpha=False`: bỏ qua khỏi kết quả (cũng không tiêu thụ keystream).

    Args:
        ciphertext: Bản mã cần giải.
        keyword: Khóa ban đầu (ít nhất một ký tự thuộc `alphabet`).
        alphabet: Bảng chữ cái (mặc định 26 chữ cái A–Z).
        keep_nonalpha: Có giữ nguyên ký tự ngoài alphabet hay không.
        mode: Kiểu autokey, "plaintext" hoặc "ciphertext".

    Returns:
        Chuỗi bản rõ đã khôi phục (giữ nguyên hoa/thường theo từng ký tự mã).

    Raises:
        ValueError: Nếu `keyword` không có ký tự hợp lệ trong `alphabet`,
                    hoặc `mode` không thuộc {"plaintext", "ciphertext"}.
    """
    ks = _normalize_key(keyword, alphabet)
    keystream = list(ks)
    out: list[str] = []
    for ch in ciphertext:
        up = ch.upper()
        if up in alphabet:
            k = keystream.pop(0) if keystream else 0
            c = alphabet.index(up)
            p_idx = (c - k) % len(alphabet)
            pch = alphabet[p_idx]

            if mode == "plaintext":
                keystream.append(p_idx)   # dùng plaintext đã khôi phục
            elif mode == "ciphertext":
                keystream.append(c)       # dùng ciphertext
            else:
                raise ValueError("mode phải là 'plaintext' hoặc 'ciphertext'.")

            out.append(pch if ch.isupper() else pch.lower())
        else:
            out.append(ch if keep_nonalpha else "")
    return "".join(out)

# (Tùy chọn) Hàm bỏ dấu để demo với tiếng Việt nếu muốn
def strip_accents(s: str) -> str:
    """Loại bỏ dấu tiếng Việt (chuẩn hoá NFD, bỏ ký tự Mn).

    Hữu ích nếu bạn muốn áp dụng Vigenère trên tiếng Việt bằng alphabet A–Z,
    chấp nhận mất thông tin thanh điệu.

    Args:
        s: Chuỗi Unicode đầu vào.

    Returns:
        Chuỗi đã bỏ dấu (và giữ nguyên các ký tự không phải chữ cái).
    """
    return ''.join(ch for ch in unicodedata.normalize('NFD', s)
                   if unicodedata.category(ch) != 'Mn')

if __name__ == "__main__":
    pt = "Attack at dawn!"
    key = "QUEENLY"

    # Autokey theo plaintext (mặc định)
    ct = vigenere_autokey_encrypt(pt, key)             # -> 'Qnxepv yt wtwp!'
    rt = vigenere_autokey_decrypt(ct, key)             # -> 'Attack at dawn!'

    # Autokey theo ciphertext
    ct2 = vigenere_autokey_encrypt(pt, key, mode="ciphertext")
    rt2 = vigenere_autokey_decrypt(ct2, key, mode="ciphertext")

    print(ct, rt)
    print(ct2, rt2)
