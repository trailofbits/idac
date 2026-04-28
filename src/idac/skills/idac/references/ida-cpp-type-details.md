# C++ Type Details

IDA can parse and handle simple C++ class declarations. It cannot parse templates and other complex constructs but simple standard cases can be parsed.

For `idac type declare`, treat the forms in this file as IDA-specific details, not as the mandatory first pass. In practice, a minimal plain-`struct` import with `ClassName_vtbl` and `__vftable` is often the safest starting point; add `__cppobj` and other refinements only after the minimal form imports cleanly.

If a C++ class contains virtual functions, IDA will try to rebuild the virtual function table (VFT) for the class. The VFT will be linked to the class by the name: if the class is called "A", the VFT type will be "A\_vtbl".

Let us consider the following class hierarchy:

```
  class A { virtual int f(); int data; };
  class B : public A { virtual int g(); };
```

IDA will create the following structures:

```
  struct __cppobj A {A_vtbl *__vftable;int data;}
  struct A_vtbl {int (*f)(A *__hidden this);}
  struct __cppobj B : A {}
  struct B_vtbl {int (*f)(A *__hidden this);
                 int (*g)(B *__hidden this);}
```

Please note that the VFT pointer in the class A has a special name: "\_\_vftable". This name allows IDA to recognize the pointer as a VFT pointer and treat it accordingly.

Another example of more complex class hierarchy:

```
  class base1 { virtual int b1(); int data; };
  class base2 { virtual int b2(); int data; };
  class der2 : public base2 { virtual int b2(); int data; };
  class derived : public base1, public der2 { virtual int d(); };
```

Compiling in 32-bit Visual Studio mode yields the following layout:

```
  class derived size(20):
        +---
   0    | +--- (base class base1)
   0    | | {vfptr}
   4    | | data
        | +---
   8    | +--- (base class der2)
   8    | | +--- (base class base2)
   8    | | | {vfptr}
  12    | | | data
        | | +---
  16    | | data
        | +---
        +---
```

IDA will generate the following types:

```
  struct __cppobj base1 {base1_vtbl *__vftable /*VFT*/;int data;};
  struct /*VFT*/ base1_vtbl {int (*b1)(base1 *__hidden this);};
  struct __cppobj base2 {base2_vtbl *__vftable /*VFT*/;int data;};
  struct /*VFT*/ base2_vtbl {int (*b2)(base2 *__hidden this);};
  struct __cppobj der2 : base2 {int data;};
  struct /*VFT*/ der2_vtbl {int (*b2)(der2 *__hidden this);};
  struct __cppobj derived : base1, der2 {};
  struct /*VFT*/ derived_vtbl {int (*b1)(base1 *__hidden this);
                               int (*d)(derived *__hidden this);};
```

The 'derived' class will use 2 VFTs:

```
  offset 0: derived_vtbl
  offset 8: der2_vtbl
```

IDA and Decompiler can use both VFTs and produce nice code for virtual calls.

Please note that the VFT layout will be different in g++ mode and IDA can handle it too. Therefore it is important to have the target compiler set correctly.

It is possible to build the class hierarchy manually. Just abide by the following rules:

* VFT pointer must have the "\_\_vftable" name
* VFT type must follow the "CLASSNAME\_vtbl" pattern

C++ classes are marked with "\_\_cppobj" keyword, it influences the class layout. However, this keyword is not required for VFT types.

In the case of a multiple inheritance it is possible to override a virtual table for a secondary base class by declaring a type with the following name: "CLASSNAME\_XXXX\_vtbl" where XXXX is the offset to the virtual table inside the derived (CLASSNAME) class.

Example: if in the above example we add one more function

```
        virtual int derived::b2();
```

then we need one more virtual table. Its name must be "derived\_0008\_vtbl". Please note that our parser does not create such vtables, you have to do it manually.


When reading raw runtime symbols on Itanium-style ABIs, distinguish between the start of the emitted virtual-table data and the virtual-table address point. The ABI explicitly says the address stored in objects "may not be the beginning of the virtual table", and that `offset_to_top` and `typeinfo` are laid out before the address point in the usual case. See the Itanium C++ ABI's [virtual table layout](https://itanium-cxx-abi.github.io/cxx-abi/abi.html#vtable) section.

That means a local IDA type such as `ClassName_vtbl` should still model the callable slots, even when the raw `__ZTV...` symbol names a wider layout blob. A useful scratch model is:

```
  struct /*VFT*/ ClassName_vtbl {
    int (*f)(ClassName *__hidden this);
  };

  struct ClassName_vtbl_layout {
    ptrdiff_t offset_to_top;
    void *typeinfo;
    ClassName_vtbl vtbl;
  };
```

Use a wrapper like `ClassName_vtbl_layout` when the apparent vtable base looks shifted by the ABI header. On common 64-bit Itanium-style layouts, the callable slots then begin at `+0x10` from the raw symbol base because `offset_to_top` and `typeinfo` occupy the first two machine words. The address actually written into an object's `__vftable` points at the address point, not necessarily at the beginning of the emitted symbol.