
# Monkey C Instruction Set Architecture (ISA)

This document describes the opcode set used by the Monkey C Virtual Machine. The machine is a stack-based architecture.
This information is intended for interoperability research, educational purposes, and the development of open-source tooling.

**Notation Key:**
*   `SP`: Stack Pointer
*   `FP`: Frame Pointer (SP at function call)
*   `BP`: Base Pointer (Pointer to the first function argument)
*   `imm8`/`imm16`/`imm24`/`imm32`: Immediate values of 8, 16, 24 or 32 bits read from the instruction stream.
*   `pop()`: Remove the top item from the stack.
*   `push(x)`: Place item `x` on top of the stack.
*   `v1`, `v2`: Temporary values popped from the stack (Order: `v2` is top, `v1` is below it).

| Hex | Mnemonic | Operands | Stack Logic | Description |
| :--- | :--- | :--- | :--- | :--- |
| **0x00** | `nop` | - | *(no change)* | **No Operation**. Performs no action. |
| **0x01** | `incsp` | `imm8` | `SP -= imm8 * 4` | **Increment Stack Pointer**. Reserves space on the stack for local variables (grows downwards). |
| **0x02** | `popv` | - | `SP += 4` | **Pop Value**. Discards the top value of the stack. |
| **0x03** | `addv` | - | `..., v1, v2` &rarr; `..., (v1 + v2)` | **Add**. Pops two values, adds them, and pushes the result. |
| **0x04** | `subv` | - | `..., v1, v2` &rarr; `..., (v1 - v2)` | **Subtract**. Pops two values, subtracts `v2` from `v1`, and pushes the result. |
| **0x05** | `mulv` | - | `..., v1, v2` &rarr; `..., (v1 * v2)` | **Multiply**. Pops two values, multiplies them, and pushes the result. |
| **0x06** | `divv` | - | `..., v1, v2` &rarr; `..., (v1 / v2)` | **Divide**. Pops two values, divides `v1` by `v2`, and pushes the result. |
| **0x07** | `andv` | - | `..., v1, v2` &rarr; `..., (v1 & v2)` | **Bitwise AND**. |
| **0x08** | `orv` | - | `..., v1, v2` &rarr; `..., (v1 \| v2)` | **Bitwise OR**. |
| **0x09** | `modv` | - | `..., v1, v2` &rarr; `..., (v1 % v2)` | **Modulo**. Computes remainder of `v1` divided by `v2`. |
| **0x0A** | `shlv` | - | `..., v1, v2` &rarr; `..., (v1 << v2)` | **Shift Left**. Shifts `v1` left by `v2` bits. |
| **0x0B** | `shrv` | - | `..., v1, v2` &rarr; `..., (v1 >> v2)` | **Shift Right**. Shifts `v1` right by `v2` bits. |
| **0x0C** | `xorv` | - | `..., v1, v2` &rarr; `..., (v1 ^ v2)` | **Bitwise XOR**. |
| **0x0D** | `getv` | - | `..., obj, prop` &rarr; `..., val` | **Get Property**. Pops object and property symbol, pushes `object.property`. |
| **0x0E** | `putv` | - | `..., obj, prop, val` &rarr; `...` | **Set Property**. Pops object, property symbol, and value. Sets `object.property = value`. |
| **0x0F** | `invokem` | `imm8` | `..., ptr, args` &rarr; `..., ret` | **Invoke Method**. Calls function with `imm8` arguments.<br>1. Calculates func ptr at `SP + imm8 * 4`.<br>2. Calls function.<br>3. Cleans up stack (`SP += (imm8+1)*4`).<br>4. Pushes return value. |
| **0x10** | `agetv` | - | `..., arr, idx` &rarr; `..., val` | **Array Get**. Pops array symbol and index. Pushes `array[index]`. |
| **0x11** | `aputv` | - | `..., arr, idx, val` &rarr; `...` | **Array Put**. Pops array symbol, index, and value. Sets `array[index] = value`. |
| **0x12** | `lgetv` | `imm8` | `...` &rarr; `..., val` | **Local Get**. Pushes value of local variable at index `imm8`.<br>*Note: `local[0]` is always `this`.* |
| **0x13** | `lputv` | `imm8` | `..., val` &rarr; `...` | **Local Put**. Pops value and stores it in local variable at index `imm8`.<br>*Note: `local[0]` is always `this`.*  |
| **0x14** | `newa` | - | `..., size` &rarr; `..., ptr` | **New Array**. Pops size, creates new array, pushes pointer. |
| **0x15** | `newc` | - | `..., class` &rarr; `..., ptr` | **New Class**. Pops class symbol, creates instance, pushes pointer. |
| **0x16** | `return` | - | `..., ret` &rarr; *(empty)* | **Return**. Pops return value, restores `SP` to `FP`, and returns to caller. |
| **0x17** | `ret` | - | - | **Ret**. Alternative return instruction (Usage context unconfirmed). |
| **0x18** | `news` | `imm32` | `...` &rarr; `..., str` | **New String**. Creates string object from string table at offset `imm32`. |
| **0x19** | `goto` | `dest16` | - | **Goto (Relative)**. Unconditional jump to `CurrentOffset + dest16`. |
| **0x1A** | `eq` | - | `..., v1, v2` &rarr; `..., bool` | **Equals**. Pushes `true` if `v1 == v2`, else `false`. |
| **0x1B** | `lt` | - | `..., v1, v2` &rarr; `..., bool` | **Less Than**. Pushes `true` if `v1 < v2`. |
| **0x1C** | `lte` | - | `..., v1, v2` &rarr; `..., bool` | **Less Than or Equal**. Pushes `true` if `v1 <= v2`. |
| **0x1D** | `gt` | - | `..., v1, v2` &rarr; `..., bool` | **Greater Than**. Pushes `true` if `v1 > v2`. |
| **0x1E** | `gte` | - | `..., v1, v2` &rarr; `..., bool` | **Greater Than or Equal**. Pushes `true` if `v1 >= v2`. |
| **0x1F** | `ne` | - | `..., v1, v2` &rarr; `..., bool` | **Not Equal**. Pushes `true` if `v1 != v2`. |
| **0x20** | `isnull` | - | `..., v1` &rarr; `..., bool` | **Is Null**. Pushes `true` if `v1` is `null`. |
| **0x21** | `isa` | - | `..., obj, type` &rarr; `..., bool` | **Is Instance Of**. Checks if `object` is an instance of `type`. |
| **0x22** | `canhazplz`| - | `..., obj, prop` &rarr; `..., bool` | **Has Property**. Checks if `object` has property `prop`. |
| **0x23** | `jsr` | `dest16` | - | **Jump Subroutine**. (Control flow; details TBD). |
| **0x24** | `ts` | - | - | **No Operation**. Performs no action. |
| **0x25** | `ipush` | `imm32` | `...` &rarr; `..., val` | **Int Push**. Pushes 32-bit integer `imm32`. |
| **0x26** | `fpush` | `imm32` | `...` &rarr; `..., val` | **Float Push**. Pushes 32-bit float `imm32`. |
| **0x27** | `spush` | `imm32` | `...` &rarr; `..., sym` | **Symbol Push**. Pushes Symbol ID `imm32`. |
| **0x28** | `bt` | `dest16` | `..., cond` &rarr; `...` | **Branch if True**. Pops `cond`. If `cond != 0`, jump to `CurrentOffset + dest16`. |
| **0x29** | `bf` | `dest16` | `..., cond` &rarr; `...` | **Branch if False**. Pops `cond`. If `cond == 0`, jump to `CurrentOffset + dest16`. |
| **0x2A** | `frpush` | - | `...` &rarr; `..., ref` | **Function Ref Push**. Pushes current function context/reference (for `invokem`). |
| **0x2B** | `bpush` | `imm8` | `...` &rarr; `..., bool` | **Bool Push**. Pushes `true` if `imm8 > 0`, else `false`. |
| **0x2C** | `npush` | - | `...` &rarr; `..., null` | **Null Push**. Pushes `null` reference. |
| **0x2D** | `invv` | - | `..., v1` &rarr; `..., ~v1` | **Invert**. Bitwise NOT / Inversion of `v1`. |
| **0x2E** | `dup` | `imm8` | `...` &rarr; `..., val` | **Duplicate**. Copies value from stack depth `imm8` (0-indexed from top) and pushes it. |
| **0x2F** | `newd` | - | `..., size` &rarr; `..., ptr` | **New Dictionary**. Pops size, creates HashMap, pushes pointer. |
| **0x30** | `getm` | - | `..., sym` &rarr; `..., mod` | **Get Module**. Pops module symbol, pushes module object pointer. |
| **0x31** | `lpush` | `imm64` | `...` &rarr; `..., val` | **Long Push**. Pushes 64-bit integer `imm64`. |
| **0x32** | `dpush` | `imm64` | `...` &rarr; `..., val` | **Double Push**. Pushes 64-bit float `imm64`. |
| **0x33** | `throw` | - | - | **Throw Exception**. |
| **0x34** | `cpush` | `imm32` | `...` &rarr; `..., char` | **Char Push**. Pushes 32-bit char value `imm32`. |
| **0x35** | `argc` | `imm8` | - | **Argument Count**. Sets up frame.<br>`BP = SP + imm8 * 4`. `FP = SP`.<br>(Sets `local[0]` / `this` relative to arguments). |
| **0x36** | `newba` | - | `..., size` &rarr; `..., ptr` | **New ByteArray**. Pops size, creates byte array, pushes pointer. |
| **0x37** | `ipushz` | - | `...` &rarr; `..., 0` | **Int Push Zero**. Pushes integer `0`. |
| **0x38** | `ipush1` | `imm8` | `...` &rarr; `..., val` | **Int Push Byte**. Pushes 8-bit integer extended to stack width. |
| **0x39** | `ipush2` | `imm16` | `...` &rarr; `..., val` | **Int Push Short**. Pushes 16-bit integer extended to stack width. |
| **0x3A** | `ipush3` | `imm24` | `...` &rarr; `..., val` | **Int Push 24**. Pushes 24-bit integer extended to stack width. |
| **0x3B** | `fpushz` | - | `...` &rarr; `..., 0.0` | **Float Push Zero**. Pushes float `0.0`. |
| **0x3C** | `lpushz` | - | `...` &rarr; `..., 0L` | **Long Push Zero**. Pushes long `0`. |
| **0x3D** | `dpushz` | - | `...` &rarr; `..., 0.0` | **Double Push Zero**. Pushes double `0.0`. |
| **0x3E** | `btpush` | - | `...` &rarr; `..., true` | **Bool Push True**. Pushes `true`. |
| **0x3F** | `bfpush` | - | `...` &rarr; `..., false` | **Bool Push False**. Pushes `false`. |
| **0x40** | `apush` | `imm32` | `...` &rarr; `..., ptr` | **Array Push**. Fetches array from global/const offset `imm32`. |
| **0x41** | `bapush` | `imm32` | `...` &rarr; `..., ptr` | **ByteArray Push**. Fetches byte array from global/const offset `imm32`. |
| **0x42** | `hpush` | `imm32` | `...` &rarr; `..., ptr` | **Hash Push**. Fetches hashmap from global/const offset `imm32`. |
| **0x43** | `getselfv` | `imm32` | `...` &rarr; `..., val` | **Get Self Field**. Pushes `this.field_imm32`. |
| **0x44** | `getself` | - | `...` &rarr; `..., this` | **Get Self**. Pushes `this` reference. |
| **0x45** | `getmv` | `imm32, imm32_2` | `...` &rarr; `..., val` | **Get Module Field**. Pushes `module_imm32.field_imm32_2`. |
| **0x46** | `getlocalv` | `imm8, imm32` | `...` &rarr; `..., val` | **Get Local Field**. Pushes `local[imm8].field_imm32`. |
| **0x47** | `getsv` | `imm32` | `..., obj` &rarr; `..., val` | **Get Symbol Field**. Pops object, pushes `object.field_imm32`. |
| **0x48** | `invokemz` | - | `..., args` &rarr; `..., ret` | **Invoke Method Zero**. Equivalent to `frpush` + `invokem 1` (0 args + context). |
| **0x49** | `aputvdup` | - | `..., arr, i, v` &rarr; `..., arr` | **Array Put & Dup**. Sets `arr[i] = v`, then pushes `arr` pointer back to stack. |
| **0x4A** | `argcincsp` | `imm8, imm8_2` | *(composite)* | **Argc + IncSp**. Combines `argc imm8` and `incsp imm8_2` into one op. |
| **0x4B** | `isnotnull` | - | `..., v1` &rarr; `..., bool` | **Is Not Null**. Pushes `true` if `v1` is not `null`. |
| **0x4C** | `lgoto` | `imm32` | - | **Long Goto**. Absolute jump to offset `imm32`. |

## Legal and Compliance
This documentation is derived from black-box technical analysis of public resource files and observed data structures. It does not include proprietary source code, cryptographic keys, or restricted SDK binaries. This research was conducted without the use of Garmin’s proprietary source code or decompilation of protected toolchain binaries. Its purpose is to facilitate interoperability and data recovery for developers working with Monkey C resources.
