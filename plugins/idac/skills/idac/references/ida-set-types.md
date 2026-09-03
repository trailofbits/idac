# IDA Type Declaration Syntax

How IDA parses C declarations applied to functions and items — the syntax accepted by `type declare`, `type check`, `function prototype set` / `function prototype check`, and `function locals retype`. Condensed from IDA's built-in "Set type" help.

Function types are entered as C declarations. Hidden arguments (like the `this` pointer in C++) must be specified explicitly. IDA uses the type information to comment the disassembly and to improve Hex-Rays decompilation. Example:

```
    int main(int argc, const char *argv[]);
```

A bare function name from a loaded type library also resolves to its prototype — entering "LoadLibraryW" yields:

```
    HMODULE __stdcall LoadLibraryW(LPCWSTR lpLibFileName);
```

provided the corresponding type library is in memory.

IDA supports user-defined calling conventions, in which the locations of arguments and the return value are explicit. For example:

```
    int __usercall func@<ebx>(int x, int y@<esi>);
```

denotes a function whose first argument is passed on the stack (IDA calculates its offset), whose second argument is passed in ESI, and whose return value is stored in EBX. Stack locations can be specified explicitly:

```
    int __usercall runtime_memhash@<^12.4>(void *p@<^0.4>, int q@<^4.4>, int r@<^8.4>)
```

For a `__usercall` function type, either all stack locations are explicit or all are calculated automatically by IDA. General rules for user-defined prototypes:

- the return value must be in a register.
  Exception: stack locations are accepted for the `__golang` and `__usercall` calling conventions.

- if the return type is `void`, the return location must not be specified

- if an argument location is not specified, the argument is assumed to be on the stack; consequent stack locations are allocated for such arguments

- nested declarations are allowed, for example:

  ```
  int **__usercall func16@<eax>(int *(__usercall *x)@<ebx>(int, long@<ecx>, int)@<esi>);
  ```

  Here the pointer `x` is passed in the ESI register; the pointed-to function is a usercall function that expects its second argument in ECX and returns its value in EBX. The rule of thumb in such complex cases is to specify the registers just before the opening brace of the parameter list.

- registers used for location names must be valid for the current processor; register names that IDA generates on the fly are unsupported

- register pairs can be specified with a colon, like `edx:eax`

- for really complicated argument locations, use scattered argument locations; see [ida-advanced-type-annotations.md](ida-advanced-type-annotations.md)

`__userpurge` is the same as `__usercall` except that the callee cleans the stack.

The name used in the declaration is ignored by IDA.

If the default calling convention is `__golang`, explicit stack offsets are also permitted, using the same `@<^offset.size>` syntax as the `runtime_memhash` example above.

IDA supports the function attribute `format`. For example:

```
  __attribute__((format(printf,2,3)))
  int myprnt(int id, const char *format, ...);
```

declares `myprnt` as a printf-like function whose format string is the second argument and whose variadic argument list starts at the third argument.

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

For data declarations, the following custom `__attribute__((annotate(X)))` keywords have been added. They control the representation of numbers in the output:

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
| `__spoils`     | explicit spoiled-register list written before the function name, e.g. `int __usercall __spoils<ecx,edx> func@<eax>(int x);`                                                                     |
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
