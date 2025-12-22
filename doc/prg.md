
# Monkey C Binary Format Specification (PRG)
This document provides a technical breakdown of the binary Monkey C `.prg` files. This information is intended for interoperability research, educational purposes, and the development of open-source tooling.

**Version:** Unofficial Internal Research  
**Byte Order:** Big-Endian  
**End of File:** 8 Null Bytes (`0x0000000000000000`)
## 1. Constants & Enums
<a name="data-types"></a>
### 1.1 Data Types
| ID (Hex) | Type | Description |
| :--- | :--- | :--- |
| `0x00` | NULL | No value following. |
| `0x01` | INT | 32-bit signed integer. |
| `0x02` | FLOAT | 32-bit IEEE 754 float. |
| `0x03` | STRING | Offset to a String object. |
| `0x04` | OBJECT | Reference to an object instance. |
| `0x05` | ARRAY | Offset to an Array object. |
| `0x06` | METHOD | Offset to a Method definition. |
| `0x07` | CLASSDEF | Offset to a Class definition. |
| `0x08` | SYMBOL | 32-bit Symbol ID. |
| `0x09` | BOOLEAN | 1 byte (0=False, 1=True). |
| `0x0A` | MODULEDEF | Offset to a Module definition. |
| `0x0B` | HASH | Offset to a Hashmap object. |
| `0x0E` | LONG | 64-bit signed integer. |
| `0x0F` | DOUBLE | 64-bit IEEE 754 double. |
| `0x13` | CHAR | 32-bit character code. |
| `0x14` | BYTE_ARRAY | Offset to a Byte Array object. |
<a name="app-types"></a>
### 1.2 App Types
| Value | Type | 
| :--- | :--- |
| 0 | WATCH_FACE |
| 1 | WATCH_APP |
| 2 | DATAFIELD |
| 3 | WIDGET |
| 4 | BACKGROUND|
| 5 | AUDIO_CONTENT_PROVIDER_APP|
| 6 | GLANCE|
### 1.3 Virtual Address Prefixes
Monkey C uses a prefixed addressing system to point to data across different sections. When an offset is encountered in Data or Code sections, the high nibble determines the target section:
*   **`0x00xxxxxx`**: Data Section
*   **`0x10xxxxxx`**: Code Section
*   **`0x20xxxxxx`**: API Data Section (System)
*   **`0x30xxxxxx`**: API Code Section (System)
*   **`0x40xxxxxx`**: Native Methods (or Class Import Section)
*   **`0x50xxxxxx`**: Extended Code Section
*   **`0x80xxxxxx`**: Symbol Table
---
## 2. Global Section Wrapper

Every section in the `.prg` file follows this standard TLV (Type-Length-Value) structure:
| Size | Name | Description |
| :--- | :--- | :--- |
| 4 | Magic | Section Identifier (e.g., `0xD000D000`). |
| 4 | Length | Length of the data block (excluding Magic/Length fields). |
| L | Data | The actual content of the section. Zero offset for position within a section |
---
## 3. Section Data Structures
### StoreID (`0x0000001D`)
| Size | Description |
| :--- | :--- |
| 4 | Unknown |
| 16 | Store UUID |
### Header (`0xD000D000` / `0xD000D00D`)
| Size | Description |
| :--- | :--- |
| 1 | Header Version | Version of the header itself. |
| 1 | ConnectIQ Major version. |
| 1 | ConnectIQ Minor version. |
| 1 | ConnectIQ Patch version. |
| 4 | Data section offset for Background processes. |
| 4 | Code section offset for Background processes. |
| 1 | App Lock indicator (Boolean). |
| 8 | Unused (0x00). |
| 4 | Data section offset for Glance view. |
| 4 | Code section offset for Glance view. |
| 4 | Flags Bit 0: Glance Support; Bit 1: Profiling; Bit 2: Sensor Pairing. |
Offsets lower than the BG Offset belong to background processes. Offsets lower than the Glance Offset belong to the glace view. Offsets higher than the BG Offset and Glance Offset belong to the foreground application.
### Entry Points (`0x6060C0DE`)
| Size | Description |
| :--- | :--- |
| 2 | Record Count (N) |
| **Repeat N times:** | |
| 16 | Internal App UUID |
| 4 | Module ID |
| 4 | Class ID (typically AppBase) |
| 4 | Resource ID: App Name |
| 4 | Resource ID: App Icon |
| 4 | Flags: `(flags & 0xFF)` is App Type (See [Section 1.2](#app-types)) |
<a name="data-section"></a>
### Data Section (`0xDA7ABABE`)
Parse sequentially until section end.
#### ClassDef v1 (`0xC1`)
| Size | Description |
| :--- | :--- |
| 1 | Tag `0xC1` |
| 3 | Magic `0xA55DEF` |
| 4 | Extends this class from (Symbol ID) |
| 4 | Statics Symbol ID |
| 4 | Parent Symbol ID (the creator class) |
| 4 | Module Symbol ID (of this class) |
| 2 | App type flags (Bit 15 = Permission Required) |
| 1 | Fields Count (N). Number of fields/methods in this class. |
| N*4 | Field Entries  |
**Field Entry (Repeat N times):**
*   **Field Key (4 bytes):** 
    *   `Key >> 8`: Symbol ID (24 bits)
    *   `Key >> 4 & 0xF`: Flags (`&5` Module, `&1` Function, `&4` Static, `&1` Hidden, `&1` Constant).
    *   `Key & 0xF`: Type (Matches Primitive Data Types table, see [Section 1.1](#data-types)).
*   **Value (4 bytes):** Actual value (for module, symbol, int, boolean, char, long, double, float) or Offset (for class, function, array, hash, string).
#### ClassDef v2 (`0xC2`)
| Size | Description |
| :--- | :--- |
| 1 | Tag `0xC2` |
| 3 | Magic `0xA55DEF` |
| 1 | Presence Flags: `&1` Extends, `&2` Statics, `&4` Parent, `&8` Module |
| 0-16 | Conditional fields based on flags (4 bytes each) |
| 2 | AppType (same logic as v1) |
| 2 | Fields Count (N) |
| N*5 | Field Entries  |
**Field Entry (Repeat N times):**
*   **Field Key (4 bytes):** 
    *   `Key >> 8`: Symbol ID (24 bits)
    *   `Key >> 4 & 0xF`: Flags (`&5` Module, `&1` Function, `&4` Static, `&1` Hidden, `&1` Constant).
*   **FieldType (1 byte):** Type (Matches Primitive Data Types table, see [Section 1.1](#data-types))
*   **Value (4 bytes):** Actual value (for module, symbol, int, boolean, char, long, double, float) or Offset (for class, function, array, hash, string).
#### String (`0x01`)
| Size | Description |
| :--- | :--- |
| 1 | Tag `0x01` |
| 2 | Length of the string. |
| L+1 | Null-terminated string (Length field does not include `0x00`). |
#### JSON Container (`0x03`)
| Size | Description |
| :--- | :--- |
| 1 | Tag `0x03` |
| 4 | Container Length (N) |
| N | Data |
Data can be just an Array (`0xDA7ADA7A`) or an Array with string block (String block `0xABCDABCD` followed by Array `0xDA7ADA7A`)
**String block (`0xABCDABCD`):**
| Size | Description |
| :--- | :--- |
| 4 | Magic `0xABCDABCD` |
| 4 | Block Length (N) |
| N | Null-terminated strings one by one |
If the following array has a String (`0x3`) element, it's value will point to an offset inside this string block.
**Array (`0xDA7ADA7A`):**
| Size | Description |
| :--- | :--- |
| 4 | Magic `0xDA7ADA7A` |
| 4 | Block Length (N) |
| 1 | Array Type |
| 4 | Array Element Count |
| N | Array Elements |
* Array Types:
   - If `HASH (0x0B)`: Element structure: [Key Type][Key Value][Value Type][Value Value].
   - If `ARRAY (0x05)`: Element structure: [Type][Value]
   - If `BYTEARRAY (0x14)`: Sequential 1-byte values.

Element Type is always 1 byte, Value size depends on the type (e.g. INT Value is 4 bytes and NULL Type doesn't have a value).
Every Array ends with a `0x00` byte.

**Multidimensional Array Structure (Layered Serialization)**
Monkey C uses a **Level-Order (Breadth-First)** serialization for nested containers (Arrays and Hashmaps). Instead of nesting data immediately, the structure is written in "Layers." You define the contents of the current container first; if any of those contents are also containers, their definitions are written next, followed finally by the primitive data.

**Logic Flow**
1. **Header:** Read Magic, Block Length, Type, and Element Count for the root.
2. **Definitions:** For each element in the Count, read a **Type Byte**.
    - If the Type is a primitive (Int, Float, etc.), no extra info is needed here.
    - If the Type is a container (Array/Hash), a **4-byte Count** follows immediately to define the size of that sub-container.
3. **Payloads:** After all Types/Counts for that layer are defined, the actual **Values** (or nested definitions) are written in the same order.
4. **Terminator:** The entire structure ends with a `0x00` byte.

**Binary Example Breakdown**
A 2D array representing: `[[Int, Int], [Int, Int, Int]]`
| Offset | Value | Description | Layer |
| :--- | :--- | :--- | :--- |
| 0x00 | `0xDA7ADA7A` | Magic (Array) | **Header** |
| 0x04 | `0x00000031` | Block Length | |
| 0x08 | `0x05` | Array Type (Object Array) | |
| 0x09 | `0x00000002` | Root Element Count (2 sub-arrays) | |
| **0x0D** | **`0x05`** | **Element 0 Type (Array)** | **Layer 1** (Definitions) |
| 0x0E | `0x00000002` | Element 0 Count (2 elements) | |
| **0x12** | **`0x05`** | **Element 1 Type (Array)** | |
| 0x13 | `0x00000003` | Element 1 Count (3 elements) | |
| **0x17** | `0x01` | **El 0,0 Type (Int)** | **Layer 2** (Contents) |
| 0x18 | `0x00000086` | El 0,0 Value | |
| 0x1C | `0x01` | **El 0,1 Type (Int)** | |
| 0x1D | `0x00000076` | El 0,1 Value | |
| **0x21** | `0x01` | **El 1,0 Type (Int)** | |
| 0x22 | `0x00000086` | El 1,0 Value | |
| 0x26 | `0x01` | **El 1,1 Type (Int)** | |
| 0x27 | `0x00000076` | El 1,1 Value | |
| 0x2B | `0x01` | **El 1,2 Type (Int)** | |
| 0x2C | `0x00000076` | El 1,2 Value | |
| 0x30 | `0x00` | **End of Container** | **Footer** |

---
### Code Sections
**Standard (`0xC0DEBABE`):** Pure Opcode bytes (See [Opcodes](opcodes.md)).  

**Extended (`0xC0DE10AD`):**
| Size | Description |
| :--- | :--- |
| 4 | Page Size (S) |
| 4 | Number of Pages (N) |
| N*4 | List of Page Sizes 4 bytes each |
| 4 | Padding Size (M) |
| M | Null Padding |
| | **Repeat N times (Ext code offset 0x50000000 starts at the first page):** |
| S | Paged Opcode Bytes |
---
### PC to Line numbers (`0xC0DE7AB1`)
| Size | Description |
| :--- | :--- |
| 2 | Entry Count (N) |
| | **Repeat N times:** |
| 4 | PC |
| 4 | File ID |
| 4 | Symbol ID |
| 4 | Line Number |
---
### Imports (`0xC1A557B1`)
| Size | Description |
| :--- | :--- |
| 2 | Entry Count (N) |
| | **Repeat N times:** |
| 4 | Module ID |
| 4 | Class ID |
### Resources (`0xF00D600D`)
Consists of multiple symbol tables followed by resource containers.
**Symbol table structure:**
| Size | Description |
| :--- | :--- |
| 2 | Entry Count (N) |
| | **Repeat N times:** |
| 4 | Symbol ID |
| 4 | Offset relative to the start of the Resource section |
Uses a 3-tier resolution system.
#### Tier 1: Top-Level Table (Resource categories)
*  **Categories (Keys):**
    *   `0x8000A2`: Strings
    *   `0x8000A3`: Drawables
    *   `0x8000A4`: Fonts
    *   `0x8005C8`: JSON
* **Offsets:** Point to Tier 2 tables for each category

#### Tier 2 & 3: Nested Tables
*   **For Strings:** Tier 2 keys are **Language IDs** (e.g., `0x8002EB` for English). Tier 2 offsets point to Tier 3 tables (Resource ID → Data Offset).
*   **For Others:** Tier 2 keys are Resource IDs. Offsets point directly to the Resource Container.
#### Resource Containers
Each resource container starts with a **Type Byte**:
*   `0x00`: **Bitmap** (See [Bitmap](bitmap.md))
*   `0x01`: **String** (Length + Content + 00)
*   `0x02`: **Font** (See [Font](font.md))
*   `0x03`: **JSON Container** (See [Data section](#data-section))
*   `0x04`: **Animation** TODO

 **Background Resource (`0xDEFECA7E`):** Contains a Top-level Symbol Table for Background resources with offsets in the Resource Section (`0xF00D600D`).
 
 **Glance Resource (`0xD00DFACE`):** Contains a Top-level Symbol Table for Glance resources with offsets in the Resource Section (`0xF00D600D`).
 
---
### Permissions (`0x6000DB01`)
| Size | Description |
| :--- | :--- |
| 2 | Entry Count (N) |
| | **Repeat N times:** |
| 4 | Permission ID |
### Exceptions (`0x0ECE7105` / `0xEECE7105`)
| Size | Description |
| :--- | :--- |
| 2 | Entry Count (N) |
| | **Repeat N times:** |
| 3 | Try Begin Offset relative to the start of the Code section |
| 3 | Try End Offset relative to the start of the Code section |
| 3 | Handle Begin Offset relative to the start of the Code section |
### Settings (`0x5E771465`)
Consists of a single serialized Hashmap using the JSON container format (See [Data section](#data-section)).

---
### Signatures
**Developer Signature (`0xE1C0DE12`):**
| Size | Description |
| :--- | :--- |
| 512 | SHA1 Signature |
| 512 | RSA Modulus |
| 4 | RSA Exponent |
| 512 | SHA256 Signature |
**AppStore Signature (`0x00005161`):**
| Size | Description |
| :--- | :--- |
| 512 | Signature Bytes |
---
### PRG End
A valid binary must terminate with 8 null bytes (`0x0000000000000000`).

---
## 4. References & Prior Research
This research was made possible by studying the works of the following individuals and organizations:
* **Anvil Secure:** [Compromising Garmin's Sport Watches (VM Deep-Dive)](https://www.anvilsecure.com/blog/compromising-garmins-sport-watches-a-deep-dive-into-garminos-and-its-monkeyc-virtual-machine.html)
* **Atredis Partners:** [Garmin Forerunner 235 Research (Dion Blazakis)](https://www.atredis.com/blog/2020/11/4/garmin-forerunner-235-dion-blazakis)
* **markw65:** [MonkeyC Optimizer](https://github.com/markw65/monkeyc-optimizer)
* **pzl:** [CIQDB(Connect IQ Debugger)](https://github.com/pzl/ciqdb)
* **qduff:** [mcdec (MonkeyC Decompiler)](https://github.com/qduff/mcdec)

## 5. Legal Compliance
This documentation is derived from black-box technical analysis of public resource files and observed data structures. It does not include proprietary source code, cryptographic keys, or restricted SDK binaries. This research was conducted without the use of Garmin’s proprietary source code or decompilation of protected toolchain binaries. Its purpose is to facilitate interoperability and data recovery for developers working with Monkey C resources.
