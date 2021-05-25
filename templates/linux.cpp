/* 
 * {NAME}_harness.cpp
 * 
 *      Automatically generated fuzzer harness for `{NAME}` target function. Make sure to add in implementation
 *      for any other necessary functionality to make this work.
 *
 *      To build for AFL, optimal for file-based fuzzing:
 *
 *          $ clang {NAME}_harness.cpp -no-pie -o {NAME}_fuzzer -ldl
 *
 *      To build for libFuzzer, optimal for generative buffer fuzzing:
 *
 *          $ clang -DLIBFUZZER -g -fsanitize=fuzzer,address {NAME}_harness.cpp -no-pie -o {NAME}_fuzzer -ldl
 *
 *      If the target library is not dynamic instrumented, make sure to operate your
 *      fuzzer under binary-only mode, ie AFL-QEMU!!!
 */

#include <dlfcn.h>
#include <alloca.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* alias for function pointer to the target function */
typedef {RET_TYPE} (*{NAME}_t)({ARGS});

/* === Manually add any other aliases here, such as pointers responsible for freeing up resources === */

void *handle = NULL;

void CloseLibrary(void)
{
    if (handle)
        dlclose(handle);
    handle = NULL;
}


#ifdef LIBFUZZER
extern "C"
#endif
int LoadLibrary(void)
{
    handle = dlopen("{TARGET}", RTLD_LAZY);
    atexit(CloseLibrary);
    return core_handle != NULL;
}


#ifdef LIBFUZZER
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
#else
int main (int argc, char** argv)
#endif
{
    // buffer used to store final parsed fuzzed data (libFuzzer)
    int64_t *buf;

    // arbitrary pointer to file metadata
    int64_t metadata;

    // get core_handle to shared object
    if (!LoadLibrary())
        return -1;

#ifdef LIBFUZZER
    if (Size == 0)
        return 0;

    // make sure the fuzzed data is null terminated
    if (Data[Size-1] != '\x00'){
        buf = (int64_t*) alloca(Size+1);
        memset(buf, 0, Size+1);
    } else {
        buf = (int64_t*) alloca(Size);
        memset(buf, 0, Size);
    }
    memcpy(buf, Data, Size);

#else
    if (argc != 2)
        return -1;
    char *filepath = argv[1];

#endif

    /* ==== ACTUAL FUZZING LOGIC ==== */

    {NAME}_t {NAME} =
        ({NAME}_t) dlsym(handle, "{NAME}");

    {RET_TYPE} *res = {NAME}(/* TODO: fill in arguments here */);

    /* TODO: handle return value logic */
   
    return 0;
}
