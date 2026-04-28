typedef unsigned int u32;
typedef unsigned long long u64;

struct HandlerState {
  u32 width;
  u32 height;
  u32 flags;
};

struct WorkerInitData {
  int cookie;
  const char *path;
};

struct Worker;
struct Handler;
struct Handler_Text;
struct Handler_Stream;
struct LegacyGroup__Handler_Pack;

struct /*VFT*/ Worker_vtbl {
  void (__fastcall *dtor)(Worker *__hidden this);
  int (__fastcall *decode)(Worker *__hidden this);
};

struct __cppobj Worker {
  struct Worker_vtbl *__vftable;
};

struct /*VFT*/ Handler_vtbl {
  void (__fastcall *dtor)(Handler *__hidden this);
  bool (__fastcall *acceptBuffer)(Handler *__hidden this, const unsigned char *bytes, u64 length, const char *category, u32 options);
  int (__fastcall *computeCount)(Handler *__hidden this, int session, int dict, int *status, u32 *count);
  int (__fastcall *refreshState)(
      Handler *__hidden this, int session, HandlerState *state, int primary, int secondary, int tertiary, int *status);
  bool (__fastcall *compareFlags)(Handler *__hidden this, u32 lhs, u32 rhs);
  Worker *(__fastcall *createWorker1)(Handler *__hidden this, const WorkerInitData *init_data);
  Worker *(__fastcall *createWorker2)(Handler *__hidden this, int plus, u64 a3, u64 a4);
  bool (__fastcall *hasCustomCountProc)(const Handler *__hidden this);
  bool (__fastcall *hasCustomStateProc)(const Handler *__hidden this);
  bool (__fastcall *hasCustomFlagProc)(const Handler *__hidden this);
};

struct __cppobj Handler {
  struct Handler_vtbl *__vftable;
  const char *category_names;
  const char *aliases;
  u32 kind_code;
  u64 probe_size;
  u64 minimum_size;
  bool include_in_catalog;
};

struct /*VFT*/ Handler_Text_vtbl : Handler_vtbl {};
struct __cppobj Handler_Text : Handler {};

struct /*VFT*/ Handler_Stream_vtbl : Handler_vtbl {};
struct __cppobj Handler_Stream : Handler {
  u32 primary_hits;
  u32 secondary_hits;
  u32 retry_hits;
  u32 bytes_remaining;
  bool saw_marker;
  bool in_batch;
  bool has_result;
};

struct /*VFT*/ LegacyGroup__Handler_Pack_vtbl : Handler_vtbl {};
struct __cppobj LegacyGroup__Handler_Pack : Handler {
  u32 match_mask;
};

struct __cppobj HandlerRegistry {
  Handler_Text text;
  Handler_Stream stream;
  LegacyGroup__Handler_Pack pack;
};
