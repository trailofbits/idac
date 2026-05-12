# Set type…

Set type information for an item or current function.
This command allows you to specify the type of the current item.
If the cursor is located on a name, the type of the named item will be edited. Otherwise, the current function type (if there is a function) or the current item type (if it has a name) will be edited.

The function type must be entered as a C declaration. Hidden arguments (like 'this' pointer in C++) should be specified explicitly. IDA will use the type information to comment the disassembly with the information about function arguments. It can also be used by the Hex-Rays decompiler plugin for better decompilation. Here is an example of a function declaration:

```
    int main(int argc, const char *argv[]);
```

It is also possible to specify a function name coming from a type library. For example, if entering "LoadLibraryW" would yield its prototype:

```
    HMODULE __stdcall LoadLibraryW(LPCWSTR lpLibFileName);
```

provided that the corresponding type library is in memory.
To delete a type declaration, just enter an empty string.
IDA supports the user-defined calling convention. In this calling convention, the user can explicitly specify the locations of arguments and the return value. For example:

```
    int __usercall func@<ebx>(int x, int y@<esi>);
```

denotes a function with 2 arguments: the first argument is passed on the stack (IDA automatically calculates its offset) and the second argument is passed in the ESI register and the return value is stored in the EBX register. Stack locations can be specified explicitly:

```
    int __usercall runtime_memhash@<^12.4>(void *p@<^0.4>, int q@<^4.4>, int r@<^8.4>)
```

There is a restriction for a __usercall function type: all stack locations should be specified explicitly or all are automatically calculated by IDA. General rules for the user defined prototypes are:

- the return value must be in a register.
  Exception: stack locations are accepted for the __golang and __usercall calling conventions.

- if the return type is 'void', the return location must not be specified

- if the argument location is not specified, it is assumed to be on the stack; consequent stack locations are allocated for such arguments

- it is allowed to declare nested declarations, for example:

  ```
  int **__usercall func16@<eax>(int *(__usercall *x)@<ebx>(int, long@<ecx>, int)@<esi>);
  ```

  Here the pointer "x" is passed in the ESI register;
  The pointed function is a usercall function and expects its second
  argument in the ECX register, its return value is in the EBX register.
  The rule of thumb to apply in such complex cases is to specify the
  the registers just before the opening brace for the parameter list.

- registers used for the location names must be valid for the current
  processor; some registers are unsupported (if the register name is
  generated on the fly, it is unsupported; inform us about such cases;
  we might improve the processor module if it is easy)

- register pairs can be specified with a colon like `edx:eax`

- for really complicated cases this syntax can be used. IDA also understands the "__userpurge" calling convention. It is the same thing as __usercall, the only difference is that the callee cleans the stack.

The name used in the declaration is ignored by IDA.
If the default calling convention is __golang then explicit specification of stack offsets is permitted. For example:

```
  __attribute__((format(printf,2,3)))
  int myprnt(int id, const char *format, ...);
```

This declaration means that myprnt is a print-like function; the format string is the second argument and the variadic argument list starts at the third argument.

Below is the full list of attributes that can be handled by IDA.

| Attribute   | Description                                        |
| ----------- | -------------------------------------------------- |
| `packed`    | pack structure/union fields tightly, without gaps  |
| `aligned`   | specify the alignment                              |
| `noreturn`  | declare as not returning function                  |
| `ms_struct` | use microsoft layout for the structure/union       |
| `format`    | possible formats: printf, scanf, strftime, strfmon |

Use `packed` only when the recovered offsets prove that normal ABI alignment would insert gaps that are not present in the binary. For example:

```
struct __attribute__((packed)) WireHeader {
  unsigned char tag;
  unsigned int length;
};
```

If the binary has a real unknown region between known fields, keep explicit padding instead of marking the whole type packed.

## Data Declaration Keywords

For data declarations, the following custom `__attribute((annotate(X)))` keywords have been added. The control the representation of numbers in the output:

| Keyword       | Description                                       |
| ------------- | ------------------------------------------------- |
| `__bin`       | unsigned binary number                            |
| `__oct`       | unsigned octal number                             |
| `__hex`       | unsigned hexadecimal number                       |
| `__dec`       | signed decimal number                             |
| `__sbin`      | signed binary number                              |
| `__soct`      | signed octal number                               |
| `__shex`      | signed hexadecimal number                         |
| `__udec`      | unsigned decimal number                           |
| `__float`     | floating point                                    |
| `__char`      | character                                         |
| `__segm`      | segment name                                      |
| `__enum()`    | enumeration member (symbolic constant)            |
| `__off`       | offset expression (a simpler version of __offset) |
| `__offset()`  | offset expression                                 |
| `__strlit()`  | string                                            |
| `__stroff()`  | structure offset                                  |
| `__custom()`  | custom data type and format                       |
| `__invsign`   | inverted sign                                     |
| `__invbits`   | inverted bitwise                                  |
| `__lzero`     | add leading zeroes                                |
| `__tabform()` | tabular form                                      |

## Type Declaration Keywords

The following additional keywords can be used in type declarations:

| Keyword        | Description                                                                                                                                                                                     |
| -------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `_BOOL1`       | a boolean type with explicit size specification (1 byte)                                                                                                                                        |
| `_BOOL2`       | a boolean type with explicit size specification (2 bytes)                                                                                                                                       |
| `_BOOL4`       | a boolean type with explicit size specification (4 bytes)                                                                                                                                       |
| `__int8`       | a integer with explicit size specification (1 byte)                                                                                                                                             |
| `__int16`      | a integer with explicit size specification (2 bytes)                                                                                                                                            |
| `__int32`      | a integer with explicit size specification (4 bytes)                                                                                                                                            |
| `__int64`      | a integer with explicit size specification (8 bytes)                                                                                                                                            |
| `__int128`     | a integer with explicit size specification (16 bytes)                                                                                                                                           |
| `_BYTE`        | an unknown type; the only known info is its size: 1 byte                                                                                                                                        |
| `_WORD`        | an unknown type; the only known info is its size: 2 bytes                                                                                                                                       |
| `_DWORD`       | an unknown type; the only known info is its size: 4 bytes                                                                                                                                       |
| `_QWORD`       | an unknown type; the only known info is its size: 8 bytes                                                                                                                                       |
| `_OWORD`       | an unknown type; the only known info is its size: 16 bytes                                                                                                                                      |
| `_TBYTE`       | 10-byte floating point value                                                                                                                                                                    |
| `_UNKNOWN`     | no info is available                                                                                                                                                                            |
| `__pure`       | pure function: always returns the same value and does not modify memory in a visible way                                                                                                        |
| `__noreturn`   | function does not return                                                                                                                                                                        |
| `__usercall`   | user-defined calling convention; see above                                                                                                                                                      |
| `__userpurge`  | user-defined calling convention; see above                                                                                                                                                      |
| `__golang`     | golang calling convention                                                                                                                                                                       |
| `__swiftcall`  | swift calling convention                                                                                                                                                                        |
| `__spoils`     | explicit spoiled-reg specification; see above                                                                                                                                                   |
| `__hidden`     | hidden function argument; this argument was hidden in the source code (e.g. 'this' argument in c++ methods is hidden)                                                                           |
| `__return_ptr` | pointer to return value; implies hidden                                                                                                                                                         |
| `__struct_ptr` | was initially a structure value                                                                                                                                                                 |
| `__array_ptr`  | was initially an array                                                                                                                                                                          |
| `__unused`     | unused function argument                                                                                                                                                                        |
| `__cppobj`     | a c++ style struct; the struct layout depends on this keyword                                                                                                                                   |
| `__ptr32`      | explicit pointer size specification (32 bits)                                                                                                                                                   |
| `__ptr64`      | explicit pointer size specification (64 bits)                                                                                                                                                   |
| `__shifted`    | shifted pointer declaration                                                                                                                                                                     |
| `__high`       | high level prototype (does not explicitly specify hidden arguments like 'this', for example) this keyword may not be specified by the user but IDA may use it to describe high level prototypes |
| `__bitmask`    | a bitmask enum, a collection of bit groups                                                                                                                                                      |
| `__tuple`      | a tuple, a special kind of struct. tuples behave like structs but have more relaxed comparison rules: the field names and alignments are ignored.                                               |
