# Technical Specification: Monkey C Binary Bitmap Specification
This document provides a technical breakdown of the binary bitmap container found in Monkey C `.prg` files. This information is intended for interoperability research, educational purposes, and the development of open-source tooling.

---
## 1. Structure Overview
The bitmap resource is a contiguous binary block consisting of four potential segments:
1. **Header** (Fixed 21 bytes)
2. **Transform Map / Palette** (Optional, variable length)
3. **Pixel Data** (Variable length, potentially compressed)
4. **Alpha Channel Map** (Optional, 1 byte per pixel)
---
## 2. The Binary Header
The header is 21 bytes long, encoded in **Big-Endian** byte order.
| Offset | Length | Name | Description |
| :--- | :--- | :--- | :--- |
| 0x00 | 4 | Magic Number | Constant: `0x0C11EE5E` (Decimal `202501726`). |
| 0x04 | 4 | Total Size | Size of the entire structure (excluding this field and Magic). |
| 0x08 | 2 | Width | Image width in pixels. |
| 0x0A | 2 | Height | Image height in pixels. |
| 0x0C | 2 | Padding | Usually `0xFFFF`. |
| 0x0E | 2 | Flags | Bitmask defining  features (see [Section 2.1](#bitmask-flags)). |
| 0x10 | 2 | Bytes Per Line | Stride (row width in bytes including padding). |
| 0x12 | 1 | BPP | Bits Per Pixel (1, 2, 4, 8, or 16). |
| 0x13 | 2 | Palette Count | Number of 4-byte entries in the Transform Map. |
<a name="bitmask-flags"></a>
### 2.1 Flags Bitmask Reference
| Bit | Hex Value | Meaning |
| :--- | :--- | :--- |
| 0 | `0x0001` | **Alpha Map Present**: A raw 8-bit alpha map follows pixel data. |
| 3 | `0x0008` | **Compressed**: Pixel data is compressed using custom LZW(see [Section 5](#lzw-custom)). |
| 13 | `0x2020` | **Direct Color Palette**: Transform map contains raw color bits (ARGB). |
---
## 3. The Transform Map (Mini-Palette)
If `Palette Count > 0`, this block follows the header. It contains a list of unique colors used in the image.
*   **Entry Length:** 4 bytes per entry (32-bit Integer).
*   **Total Length:** `Palette Count * 4` bytes.
### Color Modes
The interpretation of the Transform Map depends on the **Direct Color Flag (`0x2020`)**:
1.  **Hardware Palette Mode** (Flag `0x2020` is **OFF**):
    The value is an index (0-65) into a device-specific hardware palette (64-color, 14-color, etc.).
2.  **Direct Color Mode** (Flag `0x2020` is **ON**):
    The value is a packed color value. If BPP is 1 or 8, these are usually **ARGB2222** (8-bit). If BPP is 16, these are **ARGB1555**.
---
## 4. Pixel Data Segment
Pixel data starts after the Transform Map.
### Row Alignment and Stride
Rows are padded to the width specified in the **Bytes Per Line** header field. 
*   **Alignment:** Usually 4 or 8 bytes depending on target device GPU support.
*	**True Width:** `ceil(Width * BPP / 8)` bytes.
*   **Calculation:** If `TrueWidth < BytesPerLine`, skip `BytesPerLine - TrueWidth` bytes at the end of every row.
### Bit Packing
Pixels are packed **Least Significant Bit (LSB) first**.
*   **Example (BPP 1):** Byte `0x01` (`00000001`) contains 8 pixels. The first pixel is the rightmost bit (`1`).
*   **Example (BPP 16):** Pixels are stored as 16-bit shorts in **Little-Endian**.
---
<a name="lzw-custom"></a>
## 5. Compression Algorithm (LZW-Custom)
If flag `0x0008` is set, the pixel data is compressed. ### Compression Header
1. **Format ID** (1 byte): `0x10`.
2. **Max Code Width** (1 byte): Usually `8` or `10`.
3. **Byte Map Count** (1 byte): Number of unique bytes used in the image.
4. **Byte Map** (Variable): A list of `ByteMapCount` bytes mapping dictionary indices to actual byte values.
### Algorithm Detail:
It is a modified LZW (Lempel-Ziv-Welch) algorithm.
1.  **Byte Mapping:** The payload contains a `ByteMap` of length `ByteMapCount`. Dictionary symbols map to indices in this map, which then map to actual 0-255 byte values.
2.  **Variable Bit Width:** Codes start at a minimum bit width (calculated from `ByteMapCount`) and increment as the dictionary grows, up to `MaxBitWidth`.
3.  **Dictionary Reset:** When the dictionary reaches `(1 << MaxBitWidth)`, it is cleared and reset to its initial state.
---
## 6. Direct Color Bit Layouts
When interpreting "Direct Color" values (either from the Transform Map or 16-BPP pixels):
| Format | Bit Layout | Description |
| :--- | :--- | :--- |
| **ARGB2222** | `AA RR GG BB` | 2 bits per channel (8-bit total). |
| **ARGB1555** | `A RRRRR GGGGG BBBBB` | 1 bit Alpha, 5 per RGB (16-bit total). |
| **RGB565** | `RRRRR GGGGGG BBBBB` | 5 Red, 6 Green, 5 Blue (16-bit total). |
| **RGB332** | `RRR GGG BB` | 3 Red, 3 Green, 2 Blue (8-bit total). |
---
## 7. Alpha Channel Map
If flag `0x0001` is set, a raw 8-bit alpha map is appended to the end of the container (after the pixel data).
*   **Format:** 1 byte per pixel.
*   **Order:** Scanline (Top-Left to Bottom-Right).
*   **Length:** `Width * Height` bytes.
*   **Values:** `0x00` (Fully Transparent) to `0xFF` (Fully Opaque).
*   **Processing:** This map overrides any alpha information contained in the pixel bits or Transform Map.
---
## 8. Summary of Parsing Logic
1. Read 21-byte Header.
2. If `PaletteCount > 0`, read `PaletteCount * 4` bytes into `TransformMap`.
3. Read the remaining data. If compressed, decompress using the LZW ByteMap logic.
4. For each pixel:
    - Extract raw bits.
    - Look up value in `TransformMap`.
    - If `Flag 0x2020` is set OR `TransformMap` is null, treat value as **Direct Color**.
    - If `Flag 0x2020` is unset, treat value as **Hardware Palette Index**.
5. If `Alpha Flag` is set, read final buffer and apply to pixel Alpha channels.
---
## 9. Legal and Compliance
This documentation is derived from black-box technical analysis of public resource files and observed data structures. It does not include proprietary source code, cryptographic keys, or restricted SDK binaries. This research was conducted without the use of Garmin’s proprietary source code or decompilation of protected toolchain binaries. Its purpose is to facilitate interoperability and data recovery for developers working with Monkey C resources.