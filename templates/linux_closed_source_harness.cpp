/* 
 * {NAME}_{function_name}_harness.cpp
 * 
 *      Automatically generated fuzzer harness for `{function_name}` in `{NAME}`. Make sure to add in implementation
 *      for any other necessary functionality to make this work.
 * 
 *      Make sure the target binary/shared object is in the same directory!
 *
 *      To build for AFL-QEMU, optimal for black-box and file-based fuzzing:
 *
 *          $ clang {NAME}_{function_name}_harness.cpp -no-pie -o {NAME}_{function_name}_harness -ldl
 * 
 *          # check out more binary fuzzing strategies at https://aflplus.plus/docs/binaryonly_fuzzing/
 *          $ afl-fuzz -Q -m none -i <SEEDS> -o out/ -- ./{NAME}_{function_name}_harness
 *
 *      To build for libFuzzer, optimal for generative buffer fuzzing:
 *
 *          $ clang -DLIBFUZZER -g -fsanitize=fuzzer,address {NAME}_{function_name}_harness -no-pie -o {NAME}_{function_name}_harness -ldl
 *          $ ./{NAME}_{function_name}_harness
 *
 */

#include <dlfcn.h>
#include <alloca.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

#define FUZZER_BUF 1024 * 1024
#define TARGET_NAME "{function_name}"

// TODO: Uncomment this if you want to pass files in as inputs to the target
//#define FILE_FUZZING 1

// TODO: Uncomment this if you want to switch on using libFuzzer instead
//#define LIBFUZZER 1

/* alias for function pointer to the target function */
typedef {return_type} (*{function_name})({type_args});

// TODO: Manually add any other aliases here, such as pointers responsible for freeing up resources

void* handle = NULL;

void CloseLibrary(void)
{{
    if (handle)
        dlclose(handle);
    handle = NULL;
}}


#ifdef LIBFUZZER
extern "C"
#endif
int LoadLibrary(void)
{{
    handle = dlopen("./{NAME}", RTLD_LAZY);
    atexit(CloseLibrary);
    return handle != NULL;
}}

static uint8_t fuzzBuffer[FUZZER_BUF];

#ifdef LIBFUZZER
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* Data, size_t Size)
#else
int main (int argc, char** argv)
#endif
{{
    if (!LoadLibrary())
        return -1;

    int read_fd = 0;

#ifndef LIBFUZZER
  #ifdef FILE_FUZZING
    if (argc != 2)
        return -1;

    const char* filepath = argv[1];
    read_fd = open(filepath, O_RDONLY);
    if (read_fd < 0)
        return -1;
  #endif

    ssize_t Size = read(read_fd, fuzzBuffer, FUZZER_BUF);
    if (Size < 0)
        return -1;
#endif

    {function_name} target = ({function_name}) dlsym(handle, TARGET_NAME);
    printf("%s=%p\n", TARGET_NAME, target);

    ////////////////////////////
    // FUZZER ENTRY HERE
    ////////////////////////////

    // Harness generation currently assumes that the only arguments
    // are a pointer to the buffer and the size. Make necessary modifications
    // here to ensure the function being called has the right arguments.
    //void *res = target(fuzzBuffer, Size);

    // Introduce other functionality, ie. freeing objects, checking return values.

    return 0;
}}
