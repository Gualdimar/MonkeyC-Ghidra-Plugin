# Technical Specification: Monkey C Resource Font Container
This document provides a technical breakdown of the binary font container found in Monkey C `.prg` files. This information is intended for interoperability research, educational purposes, and the development of open-source tooling.

---
## 1. Global Header
Every font resource begins with a fixed-size header (Big-Endian).
| Offset | Field | Type | Description |
| :--- | :--- | :--- | :--- |
| 0x00 | `Sentinel` | Int32 | `0x0000F23B` (Decimal: 62011). Identifies Unicode version. |
| 0x04 | `Line Height` | Int32 | The total height of one line in pixels. |
| 0x08 | `Ascent` | Int32 | The distance from the top of the line to the baseline. |
| 0x0C | `Internal Leading`| Int32 | Vertical space for accents (Ascent - Digit Height). |
| 0x10 | `BPP` | Byte | Bits Per Pixel. Valid values: `1, 2, 4, 8`. |
| 0x11 | `Flags` | Byte | Bitwise flags. See [Section 2.1](#cmap-header). |
| 0x12 | `Glyph Count` | Int32 | Number of individual glyph bitmaps stored. |
| 0x16 | `Total Data Size` | Int32 | The expected size of the pixel blob after decompression. |
### 1.1 Flags Byte
*   **Bits 0-2 (Orientation):** Enum ordinals: `0=0°, 1=90°, 2=180°, 3=270°`. Pixels in the bitmap block are stored rotated relative to this value.
*   **Bit 3 (RLE):** If `1`, individual glyphs are RLE compressed (only if the Data Sentinel is `RAW`).
*   **Bit 4 (GPU):** While not explicitly a flag, GPU alignment is determined by the Offset Heuristic (see [Section 6.1](#atlas-image)).
---
## 2. Character Mapping (CMAP)
Located immediately after the header. This section maps Unicode points to indices in the Glyph Table.
<a name="cmap-header"></a>
### 2.1 CMAP Header
| Field | Size | Description |
| :--- | :--- | :--- |
| `Format` | 2 bytes | Usually `0x000C` (12). |
| `Reserved` | 2 bytes | Always `0x0000`. |
| `Length` | 4 bytes | Total length of the CMAP section. |
| `Language` | 4 bytes | Usually `0x00000000`. |
| `Num Groups` | 4 bytes | Number of range groups following this header. |
### 2.2 CMAP Groups (12 bytes per group)
Each group defines a contiguous range of Unicode characters.
1.  **Start Char Code** (Int32): The first Unicode ID in this range (e.g., `0x0030` for '0').
2.  **End Char Code** (Int32): The last Unicode ID in this range.
3.  **Start Glyph Index** (Int32): The index in the Glyph Table corresponding to the Start Char Code.
---
## 3. Glyph Lookup Table
Contains pointers and dimensions for every glyph.
**Entry Structure (4 bytes):**
1.  **Offset** (3 bytes): 24-bit Big-Endian value. A pointer into the **Bitmap Data Block** (relative to the start of the  pixel data).
2.  **Width** (1 byte): The actual pixel width of the character.
---
## 4. Bitmap Data Block
This section contains the actual pixel information.
### 4.1 Block Sentinel
The bitmap section is prefixed by a 4-byte sentinel:
*   **`0xCD00000D`**: The entire block is compressed using **Zlib (Deflate)**. The next 4 bytes are the `Compressed Size`.
*   **`0xCFFFFD0D`**: The data is uncompressed (**Raw**).
### 4.2 Bit Packing (The "PNG Logic")
Pixels are packed into bytes using **Little-Endian Bit Order**.
*   Within a byte, the pixel at the lowest `x` coordinate occupies the lowest bits.
*   **Example (2-BPP):** For a byte `0x41` (Binary `01 00 00 01`):
    *   Pixel 0 ($x=0$): Value `01`
    *   Pixel 1 ($x=1$): Value `00`
    *   Pixel 2 ($x=2$): Value `00`
    *   Pixel 3 ($x=3$): Value `01`
### 4.3 Color Translation
Since these are grayscale alpha masks, the N-bit value must be scaled to 8-bit grayscale for PNG output:

$$ \text{GrayValue} = \frac{\text{PixelValue} \times 255}{2^{\text{BPP}} - 1} $$

*   **1-BPP:** $0=0, 1=255$
*   **2-BPP:** $0=0, 1=85, 2=170, 3=255$
### 4.4 RLE Compression (The "Legacy/Non-GPU" Logic)
If the `Flags` byte (Offset 0x11) has Bit 3 (`0x08`) set, and the Data Sentinel is `0xCFFFFD0D` (RAW), the individual glyphs are stored using Garmin’s symbol-based Run-Length Encoding. 
Unlike standard byte-level RLE, this algorithm operates on **N-bit symbols** and uses a **Sentinel Value** to trigger a run.

---
## 5. Memory Alignment (GPU Mode)
When compiled for devices with hardware acceleration, the bitmaps follow strict alignment rules.
### 5.1 The Offset Heuristic
To detect GPU mode:
1.  Take Glyph 0's width ($W_0$) and the font $Height$.
2.  Calculate GPU Row Stride: $S = \lceil (W_0 \times \text{BPP}) / 64 \rceil \times 8$ bytes.
3.  Calculate Padded Size: $P = S \times \text{Height}$.
4.  Round $P$ up to the nearest 64 bytes (Block Padding).
5.  If $P$ matches the `Offset` of Glyph 1, the font is in **GPU Mode**.
### 5.2 GPU Alignment Rules
1.  **Row Stride:** Every row of pixels must be a multiple of **8 bytes (64 bits)**.
2.  **Glyph Padding:** The total byte size of a single glyph's data must be a multiple of **64 bytes**.
---
## 6. Reconstruction Algorithm (Pseudocode)
<a name="atlas-image"></a>
### 6.1 Reconstruct Atlas Image
1.  Initialize a `BufferedImage` with `Width = Sum of all Glyph Widths` and `Height = Global Height`.
2.  For each Glyph Entry:
    *   **If Zlib compressed:** Decompress the whole blob first.
    *   **If RLE flag is set:** 
        *   Seek to `Glyph.Offset`.
        *   Read RLE Header (SymbolBits, RepeatBits, EscapeVal).
        *   Run the Decoding Algorithm [Section 7.2](#decoding-algorithm) to fill a raw pixel array for that glyph.
    *   **If Raw/GPU:**
        *   Determine `Stride` based on the GPU Heuristic.
        *   Unpack bits directly from the blob using the Stride logic.
    *   **Stitch:** Copy pixels into the Atlas at the current `X` offset.
    *   `CurrentX += Width`.
### 6.2 Generate .fnt File
1.  Write `common lineHeight=[Header.Height] base=[Header.Ascent]`.
2.  Unroll CMAP groups:
    *   For each group:
        *   For `Code` from `Start` to `End`:
            *   `Index = StartGlyph + (Code - Start)`.
            *   Find `X` position from atlas step.
            *   Write `char id=[Code] x=[X] y=0 width=[Glyph.Width] height=[Header.Height] xadvance=[Glyph.Width]`.
---
## 7. Symbol-Based RLE Specification
To decode the RLE stream for a glyph, you must first read the **RLE Header** found at the start of that glyph's data.
### 7.1 RLE Header (3 bytes)
| Field | Size | Description |
| :--- | :--- | :--- |
| `Symbol Bits` | 1 byte | The size of one pixel/symbol (usually matches BPP). |
| `Repeat Bits` | 1 byte | The number of bits used to store the "length" of a run. |
| `Min Count Val`| 1 byte | The "Escape" or "Sentinel" value. |
<a name="decoding-algorithm"></a>
### 7.2 The Decoding Algorithm
The decoder treats the remaining data as a continuous bit-stream.
1.  **Read Symbol:** Read $N$ bits (where $N = \text{Symbol Bits}$).
2.  **Check Sentinel:**
    *   If the value **is not** equal to `Min Count Val`:
        *   This is a literal pixel. Output the value.
    *   If the value **is** equal to `Min Count Val`:
        *   Read $M$ bits (where $M = \text{Repeat Bits}$) to get the `Run Length`.
        *   Read $N$ bits (the next symbol) to get the `Run Value`.
        *   Output the `Run Value`, `Run Length` times.
3.  **Repeat** until the glyph's pixel count (Width $\times$ Height) is reached.
### 7.3 RLE Bit-Ordering
The RLE bit-stream follows the same **Little-Endian** order as the raw bitmaps. When reading $N$ bits from a byte, you start from the lowest available bits and move toward the MSB. If a symbol spans across two bytes, the remaining bits are taken from the LSB of the subsequent byte.

---
## 8. Legal and Compliance
This documentation is derived from black-box technical analysis of public resource files and observed data structures. It does not include proprietary source code, cryptographic keys, or restricted SDK binaries. This research was conducted without the use of Garmin’s proprietary source code or decompilation of protected toolchain binaries. Its purpose is to facilitate interoperability and data recovery for developers working with Monkey C resources.
