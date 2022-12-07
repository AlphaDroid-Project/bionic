/*
 * Copyright (C) 2012 The Android Open Source Project
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <async_safe/log.h>
#include <dlfcn.h>
#include <errno.h>
#include <execinfo.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <unwind.h>

#include "private/ScopedFd.h"

/**
 * @brief This function writes char* arrays at the begining of buffer.
 * Real strings should be written from buffer + arr_size * sizeof(void*).
 * Caller should make the buffer large enough.
 *
 * @param buffer Buffer contains pointer and data.
 * @param arr_size Array size. Frame size in this file.
 * @param str_size_total Total size of strings.
 * @return int 0 if OK. Negative if error occurred.
 */
static int write_str_arr(char* buffer, size_t arr_size, size_t str_size_total);

template <typename T>
static int backtrace_symbols_write(void* const* buffer, int size, T&& write_fn);

struct StackState {
  void** frames;
  int frame_count;
  int cur_frame = 0;

  StackState(void** frames, int frame_count) : frames(frames), frame_count(frame_count) {}
};

static _Unwind_Reason_Code TraceFunction(_Unwind_Context* context, void* arg) {
  // The instruction pointer is pointing at the instruction after the return
  // call on all architectures.
  // Modify the pc to point at the real function.
  uintptr_t ip = _Unwind_GetIP(context);
  if (ip != 0) {
#if defined(__arm__)
    // If the ip is suspiciously low, do nothing to avoid a segfault trying
    // to access this memory.
    if (ip >= 4096) {
      // Check bits [15:11] of the first halfword assuming the instruction
      // is 32 bits long. If the bits are any of these values, then our
      // assumption was correct:
      //  b11101
      //  b11110
      //  b11111
      // Otherwise, this is a 16 bit instruction.
      uint16_t value = (*reinterpret_cast<uint16_t*>(ip - 2)) >> 11;
      if (value == 0x1f || value == 0x1e || value == 0x1d) {
        ip -= 4;
      } else {
        ip -= 2;
      }
    }
#elif defined(__aarch64__)
    // All instructions are 4 bytes long, skip back one instruction.
    ip -= 4;
#elif defined(__i386__) || defined(__x86_64__)
    // It's difficult to decode exactly where the previous instruction is,
    // so subtract 1 to estimate where the instruction lives.
    ip--;
#endif
  }

  StackState* state = static_cast<StackState*>(arg);
  state->frames[state->cur_frame++] = reinterpret_cast<void*>(ip);
  return (state->cur_frame >= state->frame_count) ? _URC_END_OF_STACK : _URC_NO_REASON;
}

int backtrace(void** buffer, int size) {
  if (size <= 0) {
    return 0;
  }

  StackState state(buffer, size);
  _Unwind_Backtrace(TraceFunction, &state);
  return state.cur_frame;
}

class FunctorWriteFd {
 public:
  explicit FunctorWriteFd(int _fd) : fd(_fd) {}

  bool operator()(const char* s) { return write(fd, s, strlen(s)) >= 0; }

 private:
  int fd;
};

/**
 * @brief  Write strings to an auto-enlarged buffer.
 */
class FunctorWriteDynamicBuffer {
 public:
  const static size_t INIT_BUFSIZE = 512;
  explicit FunctorWriteDynamicBuffer(size_t start_offset = 0)
      : mBuf(nullptr), mBufSize(INIT_BUFSIZE + start_offset), mPos(nullptr) {
    mBuf = static_cast<char*>(malloc(mBufSize));
    mBuf[mBufSize - 1] = '\0';
    mPos = mBuf + start_offset;
  }

  FunctorWriteDynamicBuffer(FunctorWriteDynamicBuffer&& other) {
    mBuf = other.mBuf;
    mBufSize = other.mBufSize;
    mPos = other.mPos;
    other.mBuf = other.mPos = nullptr;
    other.mBufSize = 0;
  }

  bool operator()(const char* s) {
    size_t len_to_write = strlen(s);
    size_t bytes_left = mBuf + mBufSize - mPos - 1;
    size_t curr_size = GetSizeWrite();
    if (len_to_write > bytes_left) {
      // Ensure enlarged buffer is large enough.
      mBufSize = (mBufSize + (len_to_write - bytes_left)) << 1;
      void* new_buf = realloc(mBuf, mBufSize);
      if (!new_buf) {
        error_log("Realloc failed. Maybe out of memory");
        return false;
      }
      mBuf = static_cast<char*>(new_buf);
      // mBuf may be changed after realloc so we re-calculate mPos based on mBuf.
      mPos = mBuf + curr_size;
    }
    strncat(mPos, s, len_to_write);
    // Last '\0' appended by strncat will be overriddn at next invocation.
    mPos += len_to_write;
    return true;
  }

  char* GetBuffer() { return mBuf; }

  size_t GetSizeWrite() const { return mPos - mBuf; }

  void Destroy() {
    if (mBuf) {
      free(mBuf);
      mPos = mBuf = nullptr;
      mBufSize = 0;
    }
  }

  // Disallow copy and assign.
  FunctorWriteDynamicBuffer(FunctorWriteDynamicBuffer& other) = delete;
  FunctorWriteDynamicBuffer operator=(FunctorWriteDynamicBuffer& other) = delete;

 private:
  char* mBuf;
  size_t mBufSize;
  char* mPos;
};

char** backtrace_symbols(void* const* buffer, int size) {
  size_t ptr_size;
  if (__builtin_mul_overflow(sizeof(char*), size, &ptr_size)) {
    error_log("Overflow when calculate ptr_size!");
    return nullptr;
  }

  FunctorWriteDynamicBuffer functor(ptr_size);
  int retval = backtrace_symbols_write(buffer, size, functor);
  if (retval < 0) {
    functor.Destroy();
    error_log("backtrace_symbols_write(dynamic) failed. retval: %d", retval);
    return nullptr;
  }

  size_t raw_size = functor.GetSizeWrite();
  if (write_str_arr(functor.GetBuffer(), size, raw_size) < 0) {
    functor.Destroy();
    return nullptr;
  }

  return reinterpret_cast<char**>(functor.GetBuffer());
}

// This function should do no allocations if possible.
void backtrace_symbols_fd(void* const* buffer, int size, int fd) {
  if (size <= 0 || fd < 0) {
    return;
  }

  int retval = backtrace_symbols_write(buffer, size, FunctorWriteFd(fd));
  if (retval < 0) {
    error_log("backtrace_symbols_write(fd) failed. retval: %d", retval);
  }
}

static int write_str_arr(char* symbol_data, size_t arr_size, size_t file_size) {
  size_t ptr_size = sizeof(char*) * arr_size;
  char* cur_string = reinterpret_cast<char*>(&symbol_data[ptr_size]);

  // Make sure the last character is '\n'.
  if (cur_string[file_size] != '\n') {
    cur_string[file_size++] = '\n';
  }

  for (size_t i = 0; i < arr_size; i++) {
    (reinterpret_cast<char**>(symbol_data))[i] = cur_string;
    cur_string = strchr(cur_string, '\n');
    if (cur_string == nullptr) {
      return -1;
    }
    cur_string[0] = '\0';
    cur_string++;
  }
  return 0;
}

template <typename T>
static int backtrace_symbols_write(void* const* buffer, int size, T&& write_fn) {
  const int BUFSIZE = 512;
  char buf[BUFSIZE];
  for (int frame_num = 0; frame_num < size; frame_num++) {
    void* address = buffer[frame_num];
    Dl_info info;
    if (dladdr(address, &info) != 0) {
      if (info.dli_fname != nullptr) {
        if (!write_fn(info.dli_fname)) return -1;
      }
      if (info.dli_sname != nullptr) {
        snprintf(
            buf, BUFSIZE, "(%s+0x%" PRIxPTR ") ", info.dli_sname,
            reinterpret_cast<uintptr_t>(address) - reinterpret_cast<uintptr_t>(info.dli_saddr));
        if (!write_fn(buf)) return -1;
      } else {
        snprintf(buf, BUFSIZE, "(+%p) ", info.dli_saddr);
        write_fn(buf);
      }
    }

    snprintf(buf, BUFSIZE, "[%p]\n", address);
    if (!write_fn(buf)) return -1;
  }
  return 0;
}
