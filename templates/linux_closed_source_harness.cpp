/* 
 * {NAME}_harness.cpp
 * 
 *      Automatically generated fuzzer harness for `{NAME}` target function. Make sure to add in implementation
 *      for any other necessary functionality to make this work.
 * 
 *      Make sure the target binary/shared object is in the same directory!
 *
 *      To build for AFL-QEMU, optimal for black-box, file-based fuzzing:
 *
 *          $ afl-clang {NAME}_harness.cpp -no-pie -o {NAME}_fuzzer -ldl
 * 
 *          # check out more binary fuzzing strategies at https://aflplus.plus/docs/binaryonly_fuzzing/
 *          $ afl-fuzz -Q -m none -i <SEEDS> -o out/ -- ./{NAME}_fuzzer
 *
 *      To build for libFuzzer, optimal for generative buffer fuzzing:
 *
 *          $ clang -DLIBFUZZER -g -fsanitize=fuzzer,address {NAME}_harness.cpp -no-pie -o {NAME}_fuzzer -ldl
 *          $ ./{NAME}_fuzzer
 *
 */

#include <dlfcn.h>
#include <alloca.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

#define FUZZER_BUF 1024 * 1024
#define TARGET_NAME "{NAME}"

/* alias for function pointer to the target function */
typedef target_t (*{return_type})({args});

/* === Manually add any other aliases here, such as pointers responsible for freeing up resources === */

void* handle = NULL;

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
    handle = dlopen("./{binary}", RTLD_LAZY);
    atexit(CloseLibrary);
    return handle != NULL;
}

extern uint8_t fuzzBuffer[FUZZER_BUF];

#ifdef LIBFUZZER
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* Data, size_t Size)
#else
int main (int argc, char** argv)
#endif
{    
    if (!LoadLibrary())
        return -1;

    int read_fd;

#ifndef LIBFUZZER
  #ifdef FILE_FUZZING
    if (argc != 2)
        return -1;

    const char* filepath = argv[1];
    read_fd = open(filepath, O_RDONLY);
    if (read_fd < 0)
        return -1;

  #else

    read_fd = stdin;

  #endif

    ssize_t Size = read(read_fd, fuzzBuffer, FUZZER_BUF);
    if (Size < 0)
        return -1;
#endif

    ////////////////////////////
    // FUZZER ENTRY HERE
    ////////////////////////////

    target_t function = (target_t) dlsym(handle, TARGET_NAME);
    printf("%s=%p\n", TARGET_NAME, function);

    void *res = function(fuzzBuffer, Size);

    return 0;
}
