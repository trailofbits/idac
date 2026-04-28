# Advanced Type Annotations

IDA extends standard C/C++ type declarations with specialized annotations that provide control over data interpretation and display in disassembly and decompiled code.

For a complete list of all type system keywords, see the [Type System Keywords](type-system-keywords.html)

## Shifted Pointers

Sometimes in binary code we can encounter a pointer to the middle of a structure. Such pointers usually do not exist in the source code but an optimizing compiler may introduce them to make the code shorter or faster.

Such pointers can be described using shifted pointers. A shifted pointer is a regular pointer with additional information about the name of the parent structure and the offset from its beginning. For example:

```
        struct mystruct
        {
          char buf[16];
          int dummy;
          int value;            // <- myptr points here
          double fval;
        };
        int *__shifted(mystruct,20) myptr;
```

The above declaration means that myptr is a pointer to 'int' and if we decrement it by 20 bytes, we will end up at the beginning of 'mystruct'.

Please note that IDA does not limit parents of shifted pointers to structures. A shifted pointer after the adjustment may point to any type except 'void'.

Also, negative offsets are supported too. They mean that the pointer points to the memory before the structure.

When a shifted pointer is used with an adjustment, it will be displayed with the 'ADJ' helper function. For example, if we refer to the memory 4 bytes further, it can be represented like this:

```
        ADJ(myptr)->fval
```

Shifted pointers are an improvement compared to the CONTAINING_RECORD macro because expressions with them are shorter and easier to read.

## Scattered Argument Locations

Modern compilers may pass structure arguments across multiple registers or mixed register/stack locations. Scattered argument locations describe these complex calling conventions.

```
  00000000 struc_1         struc ; (sizeof=0xC)
  00000000 c1              db ?
  00000001                 db ? ; undefined
  00000002 s2              dw ?
  00000004 c3              db ?
  00000005                 db ? ; undefined
  00000006                 db ? ; undefined
  00000007                 db ? ; undefined
  00000008 i4              dd ?
  0000000C struc_1         ends
```

If we have this function prototype:

```
  void myfunc(struc_1 s);
```

the 64bit GNU compiler will pass the structure like this:

```
  RDI: c1, s2, and c3
  RSI: i4
```

Since compilers can use such complex calling conventions, IDA needs some mechanism to describe them. Scattered argument locations are used for that. The above calling convention can be described like this:

```
  void __usercall myfunc(struc_1 s@<0:rdi.1, 2:rdi^2.2, 4:rdi^4.1, 8:rsi.4>);
```

It reads:

- **1 byte** at offset **0** of the argument is passed in **byte 0 of RDI**
- **2 bytes** at offset **2** of the argument are passed in **bytes 1–2 of RDI**
- **1 byte** at offset **4** of the argument is passed in **byte 3 of RDI**
- **4 bytes** at offset **8** of the argument are passed starting from **byte 0 of RSI**

In other words, the following syntax is used:

```
  argoff:register^regoff.size
```

where:

- **argoff** — offset within the argument
- **register** — register name used to pass part of the argument
- **regoff** — offset within the register
- **size** — number of bytes

The regoff and size fields can be omitted if there is no ambiguity.

If the register is not specified, the expression describes a stack location:

```
  argoff:^stkoff.size
```

where:

- **argoff** - offset within the argument
- **stkoff** - offset in the stack frame (the first stack argument is at offset 0)
- **size** - number of bytes

Please note that while IDA checks the argument location specifiers for soundness, it cannot perform all checks and some wrong locations may be accepted. In particular, IDA in general does not know the register sizes and accepts any offsets within them and any sizes.

See also the Set type… (action `SetType`) command.

## Data Representation Annotations

### Data representation: enum member

**Syntax**:

```
  __enum(enum_name)
```

Instead of a plain number, a symbolic constant from the specified enum will be used. The enum can be a regular enum or a bitmask enum. For bitmask enums, a bitwise combination of symbolic constants will be printed. If the value to print cannot be represented using the specified enum, it will be displayed in red.

**Example**:

```
   enum myenum { A=0, B=1, C=3 };
   short var __enum(myenum);
```

If `var` is equal to 1, it will be represented as "B"

Another example:

```
   enum mybits __bitmask { INITED=1, STARTED=2, DONE=4 };
   short var __enum(mybits);
```

If `var` is equal to 3, it will be represented as "INITED|STARTED"

This annotation is useful if the enum size is not equal to the variable size. Otherwise using the enum type for the declaration is better:

```
   myenum var;  // is 4 bytes, not 2 as above
```

### Data representation: offset expression

**Syntax**:

```
  __offset(type, base, tdelta, target)
  __offset(type, base, tdelta)
  __offset(type, base)
  __offset(type|AUTO, tdelta)
  __offset(type)
  __off
```

where `type` is one of:

| Type     | Description                       |
| -------- | --------------------------------- |
| `OFF8`   | 8-bit full offset                 |
| `OFF16`  | 16-bit full offset                |
| `OFF32`  | 32-bit full offset                |
| `OFF64`  | 64-bit full offset                |
| `LOW8`   | low 8 bits of 16-bit offset       |
| `LOW16`  | low 16 bits of 32-bit offset      |
| `HIGH8`  | high 8 bits of 16-bit offset      |
| `HIGH16` | high 16 bits of 32-bit offset     |

The type can also be the name of a custom refinfo.

It can be combined with the following keywords:

| Keyword    | Description                                                                                                                                              |
| ---------- | -------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `RVAOFF`   | based reference (rva)                                                                                                                                    |
| `PASTEND`  | reference past an item; it may point to an nonexistent address                                                                                           |
| `NOBASE`   | forbid the base xref creation; implies that the base can be any value<br>**Note:** base xrefs are created only if the offset base points to the middle of a segment |
| `SUBTRACT` | the reference value is subtracted from the base value instead of (as usual) being added to it                                                            |
| `SIGNEDOP` | the operand value is sign-extended (only supported for `REF_OFF8/16/32/64`)                                                                              |
| `NO_ZEROS` | an opval of 0 will be considered invalid                                                                                                                 |
| `NO_ONES`  | an opval of ~0 will be considered invalid                                                                                                                |
| `SELFREF`  | the self-based reference                                                                                                                                 |

The base, target delta, and the target can be omitted. If the base is BADADDR, it can be omitted by combining the type with AUTO:

```
  __offset(type|AUTO, tdelta)
```

Zero based offsets without any additional attributes and having the size that corresponds the current application target (e.g. REF_OFF32 for a 32-bit bit application), the shoft __off form can be used.

**Examples**:

- A 64-bit offset based on the image base:

```
  int var __offset(OFF64|RVAOFF);
```

- A 32-bit offset based on 0 that may point to an non-existing address:

```
  int var __offset(OFF32|PASTEND|AUTO);
```

- A 32-bit offset based on 0x400000:

```
  int var __offset(OFF32, 0x400000);
```

- A simple zero based offset that matches the current application bitness:

```
  int var __off;
```

This annotation is useful when the type of the pointed object is unknown, or the variable size is different from the usual pointer size. Otherwise, it is better to use a pointer:

```
  type *var;
```

### Data representation: string

**Syntax**:

```
  __strlit(strtype, "encoding")
  __strlit(strtype, char1, char2, "encoding")
  __strlit(strtype)
```

where strtype is one of:

| Type        | Description                                              |
| ----------- | -------------------------------------------------------- |
| `C`         | Zero-terminated string, 8 bits per symbol                |
| `C_16`      | Zero-terminated string, 16 bits per symbol               |
| `C_32`      | Zero-terminated string, 32 bits per symbol               |
| `PASCAL`    | Pascal string: 1-byte length prefix, 8 bits per symbol   |
| `PASCAL_16` | Pascal string: 1-byte length prefix, 16 bits per symbol  |
| `LEN2`      | Wide Pascal string: 2-byte length prefix, 8 bits per symbol  |
| `LEN2_16`   | Wide Pascal string: 2-byte length prefix, 16 bits per symbol |
| `LEN4`      | Delphi string: 4-byte length prefix, 8 bits per symbol   |
| `LEN4_16`   | Delphi string: 4-byte length prefix, 16 bits per symbol  |

It may be followed by two optional string termination characters (only for C). Finally, the string encoding may be specified, as the encoding name or "no_conversion" if the string encoding was not explicitly specified.

**Example**:

- A zero-terminated string in windows-1252 encoding:

```
  char array[10] __strlit(C,"windows-1252");
```

- A zero-terminated string in utf-8 encoding:

```
  char array[10] __strlit(C,"UTF-8");
```

### Data representation: structure offset

Syntax:

```
  __stroff(structname)
  __stroff(structname, delta)
```

Instead of a plain number, the name of a struct or union member will be used. If delta is present, it will be subtracted from the value before converting it into a struct/union member name.

**Example**:
An integer variable named `var` that hold an offset from the beginning of the `mystruct` structure:

```
  int var __stroff(mystruct);
```

If mystruct is defined like this:

```
  struct mystruct
  {
    char a;
    char b;
    char c;
    char d;
  }
```

The value 2 will be represented as `mystruct.c`

**Another example**:
A structure offset with a delta:

```
  int var __stroff(mystruct, 1);
```

The value 2 will be represented as `mystruct.d-1`

### Data representation: custom data type and format

**Syntax**:

```
 __custom(dtid, fid)
```

where dtid is the name of a custom data type and fid is the name of a custom data format. The custom type and format must be registered by a plugin beforehand, at the database opening time. Otherwise, custom data type and format ids will be displayed instead of names.

### Data representation: tabular form

**Syntax**:

```
  __tabform(flags)
  __tabform(flags,lineitems)
  __tabform(flags,lineitems,alignment)
  __tabform(,lineitems,alignment)
  __tabform(,,alignment)
```

This keyword is used to format arrays. The following flags are accepted:

| Flag      | Description                                  |
| --------- | -------------------------------------------- |
| `NODUPS`  | do not use the `dup` keyword                 |
| `HEX`     | use hexadecimal numbers to show array indexes |
| `OCT`     | use octal numbers to show array indexes      |
| `BIN`     | use binary numbers to show array indexes     |
| `DEC`     | use decimal numbers to show array indexes    |

It is possible to combine NODUPS with the index radix: NODUPS|HEX

The `lineitems` and `alignment` attributes have the meaning described for the Array… (action `MakeArray`) command.

**Example**:

Display the array in tabular form, 4 decimal numbers on a line, each number taking 8 positions. Display indexes as comments in hexadecimal:

```
  char array[16] __tabform(HEX,4,8) __dec;
```

A possible array may look like:

```
  dd   50462976, 117835012, 185207048, 252579084; 0
  dd  319951120, 387323156, 454695192, 522067228; 4
  dd  589439264, 656811300, 724183336, 791555372; 8
  dd  858927408, 926299444, 993671480,1061043516; 0Ch
```

Without this annotation, the `dup` keyword is permitted, number of items on a line and the alignment are not defined.
