/* 
 * {NAME}_{function_name}_harness.cpp
 * 
 *      Automatically generated fuzzer harness for `{function_name}` in `{NAME}`. Make sure to add in implementation
 *      for any other necessary functionality to make this work.
 * 
 *      Make sure the target binary/shared object is in the same directory!
 *
 *      To build for AFL, optimal for black-box and file-based fuzzing:
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
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <stdio.h>

/* DEPENDENCIES HERE */

#define FUZZER_BUF 1024 * 1024

static uint8_t fuzzBuffer[FUZZER_BUF];

int main(int argc, char** argv) 
{
    ssize_t read_bytes = read(stdin, fuzzBuffer, FUZZER_BUF);

    // setup and initialization calls

    // free memory and close file handles
}