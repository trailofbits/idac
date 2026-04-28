#include <cstddef>
#include <cstdint>
#include <cstring>

struct HandlerState {
  unsigned width;
  unsigned height;
  unsigned flags;
};

struct WorkerInitData {
  int cookie;
  const char *path;
};

struct Worker {
  virtual ~Worker() = default;
  virtual int decode() = 0;
};

struct TextWorker final : Worker {
  explicit TextWorker(int cookie) : cookie(cookie) {}
  int decode() override { return cookie + 10; }
  int cookie;
};

struct StreamWorker final : Worker {
  StreamWorker(int cookie, unsigned flags) : cookie(cookie), flags(flags) {}
  int decode() override { return cookie + static_cast<int>(flags); }
  int cookie;
  unsigned flags;
};

struct PackWorker final : Worker {
  explicit PackWorker(unsigned flags) : flags(flags) {}
  int decode() override { return static_cast<int>(flags ^ 0x2A); }
  unsigned flags;
};

class Handler {
 public:
  Handler(const char *category, const char *aliases, unsigned kind_code, std::size_t probe_size, std::size_t minimum_size)
      : category_names(category),
        aliases(aliases),
        kind_code(kind_code),
        probe_size(probe_size),
        minimum_size(minimum_size),
        include_in_catalog(true) {}

  virtual ~Handler() = default;

  virtual bool acceptBuffer(const unsigned char *bytes, std::size_t length, const char *category, unsigned options) {
    return bytes != nullptr && length >= probe_size && category != nullptr && std::strcmp(category, category_names) == 0
           && options == 0;
  }

  virtual int computeCount(int session, int dict, int *status, unsigned *count) {
    if (status != nullptr) {
      *status = session + dict + static_cast<int>(kind_code & 0xFF);
    }
    if (count != nullptr) {
      *count = 1;
    }
    return 0;
  }

  virtual int refreshState(int session, HandlerState *state, int primary, int secondary, int tertiary, int *status) {
    if (state != nullptr) {
      state->width = static_cast<unsigned>(session + primary);
      state->height = static_cast<unsigned>(secondary + tertiary);
      state->flags = kind_code;
    }
    if (status != nullptr) {
      *status = 0;
    }
    return 0;
  }

  virtual bool compareFlags(unsigned lhs, unsigned rhs) { return lhs == rhs; }

  virtual Worker *createWorker(const WorkerInitData *init_data) {
    return new TextWorker(init_data != nullptr ? init_data->cookie : 0);
  }

  virtual Worker *createWorker(int plus, std::uint64_t a3, std::uint64_t a4) {
    return new TextWorker(plus + static_cast<int>(a3 + a4));
  }

  virtual bool hasCustomCountProc() const { return false; }
  virtual bool hasCustomStateProc() const { return false; }
  virtual bool hasCustomFlagProc() const { return false; }

  const char *category() const { return category_names; }
  unsigned code() const { return kind_code; }

 protected:
  const char *category_names;
  const char *aliases;
  unsigned kind_code;
  std::size_t probe_size;
  std::size_t minimum_size;
  bool include_in_catalog;
};

class Handler_Text final : public Handler {
 public:
  Handler_Text() : Handler("catalog.text", ".txt.", 0x54455854U, 8, 8) {}
  ~Handler_Text() override = default;

  bool acceptBuffer(const unsigned char *bytes, std::size_t length, const char *category, unsigned options) override {
    return length >= 8 && bytes[0] == 'T' && bytes[1] == 'E' && bytes[2] == 'X' && bytes[3] == 'T'
           && Handler::acceptBuffer(bytes, length, category, options);
  }

  int computeCount(int session, int dict, int *status, unsigned *count) override {
    if (count != nullptr) {
      *count = static_cast<unsigned>((session ^ dict) & 3) + 1;
    }
    if (status != nullptr) {
      *status = 7;
    }
    return 0;
  }

  int refreshState(int session, HandlerState *state, int primary, int secondary, int tertiary, int *status) override {
    Handler::refreshState(session, state, primary, secondary, tertiary, status);
    if (state != nullptr) {
      state->flags |= 0x100U;
    }
    return 0;
  }

  bool hasCustomCountProc() const override { return true; }
  bool hasCustomStateProc() const override { return true; }

  Worker *createWorker(const WorkerInitData *init_data) override {
    return new TextWorker(init_data != nullptr ? init_data->cookie + 1 : 1);
  }

  Worker *createWorker(int plus, std::uint64_t a3, std::uint64_t a4) override {
    return new TextWorker(plus + static_cast<int>(a3) + static_cast<int>(a4));
  }
};

class Handler_Stream final : public Handler {
 public:
  Handler_Stream()
      : Handler("catalog.stream", ".stream.", 0x5354524DU, 18, 0),
        primary_hits(0),
        secondary_hits(0),
        retry_hits(0),
        bytes_remaining(0),
        saw_marker(false),
        in_batch(false),
        has_result(false) {}

  ~Handler_Stream() override = default;

  bool acceptBuffer(const unsigned char *bytes, std::size_t length, const char *category, unsigned options) override {
    return length >= 12 && category != nullptr && options <= 1 && bytes[0] == 'D' && bytes[1] == 'A' && bytes[2] == 'T'
           && bytes[3] == 'A' && bytes[8] == 'F' && bytes[9] == 'L' && bytes[10] == 'O' && bytes[11] == 'W';
  }

  int computeCount(int session, int dict, int *status, unsigned *count) override {
    bytes_remaining = static_cast<unsigned>(session + dict);
    primary_hits += 1U;
    secondary_hits += static_cast<unsigned>(dict & 1);
    if (count != nullptr) {
      *count = primary_hits + secondary_hits + 1U;
    }
    if (status != nullptr) {
      *status = has_result ? 0 : -1;
    }
    return 0;
  }

  int refreshState(int session, HandlerState *state, int primary, int secondary, int tertiary, int *status) override {
    retry_hits += static_cast<unsigned>(tertiary & 1);
    in_batch = ((session + primary) & 1) != 0;
    saw_marker = ((secondary + tertiary) & 2) != 0;
    has_result = bytes_remaining != 0;
    if (state != nullptr) {
      state->width = primary_hits + 640U;
      state->height = secondary_hits + 480U;
      state->flags = (saw_marker ? 0x10U : 0U) | (in_batch ? 0x20U : 0U);
    }
    if (status != nullptr) {
      *status = static_cast<int>(retry_hits);
    }
    return 0;
  }

  bool compareFlags(unsigned lhs, unsigned rhs) override { return (lhs & 0xFFU) == (rhs & 0xFFU); }
  bool hasCustomCountProc() const override { return true; }
  bool hasCustomStateProc() const override { return true; }
  bool hasCustomFlagProc() const override { return true; }

  Worker *createWorker(const WorkerInitData *init_data) override {
    return new StreamWorker(init_data != nullptr ? init_data->cookie : 0, bytes_remaining);
  }

  Worker *createWorker(int plus, std::uint64_t a3, std::uint64_t a4) override {
    return new StreamWorker(plus, static_cast<unsigned>(a3 ^ a4));
  }

  bool validateMarker(unsigned marker_type, unsigned marker_size) {
    if (marker_type == 0x44415441U) {
      ++primary_hits;
      has_result = true;
    } else if (marker_type == 0x464C4F57U) {
      ++secondary_hits;
      has_result = true;
    } else if (marker_type == 0x52455452U) {
      ++retry_hits;
      in_batch = true;
    } else if (marker_type == 0x4D41524BU) {
      saw_marker = true;
    }
    bytes_remaining = marker_size;
    return has_result;
  }

 private:
  unsigned primary_hits;
  unsigned secondary_hits;
  unsigned retry_hits;
  unsigned bytes_remaining;
  bool saw_marker;
  bool in_batch;
  bool has_result;
};

namespace LegacyGroup {

class Handler_Pack final : public Handler {
 public:
  Handler_Pack() : Handler("catalog.pack", ".pack.", 0x5041434BU, 12, 16), match_mask(0xFFU) {}
  ~Handler_Pack() override = default;

  bool acceptBuffer(const unsigned char *bytes, std::size_t length, const char *category, unsigned options) override {
    return length >= 12 && category != nullptr && (options & 1U) == 0 && bytes[4] == 'P' && bytes[5] == 'K';
  }

  bool compareFlags(unsigned lhs, unsigned rhs) override { return (lhs & match_mask) == (rhs & match_mask); }

  Worker *createWorker(const WorkerInitData *init_data) override {
    return new PackWorker(static_cast<unsigned>(init_data != nullptr ? init_data->cookie : 0));
  }

  Worker *createWorker(int plus, std::uint64_t a3, std::uint64_t a4) override {
    return new PackWorker(static_cast<unsigned>(plus) ^ static_cast<unsigned>(a3 + a4));
  }

  bool hasCustomFlagProc() const override { return true; }

 private:
  unsigned match_mask;
};

}  // namespace LegacyGroup

class HandlerRegistry {
 public:
  HandlerRegistry() : text(), stream(), pack() {}

  Handler *chooseHandler(const unsigned char *bytes, std::size_t length) {
    if (text.acceptBuffer(bytes, length, text.category(), 0)) {
      return &text;
    }
    if (stream.acceptBuffer(bytes, length, stream.category(), 0)) {
      return &stream;
    }
    if (pack.acceptBuffer(bytes, length, pack.category(), 0)) {
      return &pack;
    }
    return nullptr;
  }

 private:
  Handler_Text text;
  Handler_Stream stream;
  LegacyGroup::Handler_Pack pack;
};

extern "C" Handler *CreateHandler_Text() { return new Handler_Text(); }
extern "C" Handler *CreateHandler_Stream() { return new Handler_Stream(); }
extern "C" Handler *CreateHandler_Pack() { return new LegacyGroup::Handler_Pack(); }

extern "C" int RunHandlerFlow(const unsigned char *bytes, std::size_t length) {
  HandlerRegistry registry;
  WorkerInitData init_data{17, "fixture"};
  HandlerState state{0, 0, 0};
  int status = -1;
  unsigned count = 0;

  Handler *handler = registry.chooseHandler(bytes, length);
  if (handler == nullptr) {
    return -1;
  }

  handler->computeCount(3, 9, &status, &count);
  handler->refreshState(5, &state, 1, 2, 3, &status);
  Worker *worker = handler->createWorker(&init_data);
  int decoded = worker->decode();
  delete worker;
  return decoded + static_cast<int>(count) + status + static_cast<int>(state.flags);
}

int main() {
  static const unsigned char text_bytes[16] = {'T', 'E', 'X', 'T', '\r', '\n', 0x1A, '\n', 0, 0, 0, 0, 0, 0, 0, 0};
  static const unsigned char stream_bytes[16] = {'D', 'A', 'T', 'A', 0, 0, 0, 0, 'F', 'L', 'O', 'W', 0, 0, 0, 0};
  int total = RunHandlerFlow(text_bytes, sizeof(text_bytes));
  total += RunHandlerFlow(stream_bytes, sizeof(stream_bytes));
  Handler *pack = CreateHandler_Pack();
  WorkerInitData init_data{3, "pack"};
  Worker *worker = pack->createWorker(&init_data);
  total += worker->decode();
  delete worker;
  delete pack;
  return total & 0xFF;
}
