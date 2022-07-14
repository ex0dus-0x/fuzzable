/* 
 * {NAME}_harness.cpp
 * 
 *      Automatically generated fuzzer harness for `{NAME}` target function. Make sure to add in implementation
 *      for any other necessary functionality to make this work.
 *
 *      To build for AFL++:
 *
 *          $ AFL_USE_ASAN=1 afl-clang {NAME}_harness.cc -no-pie -o {NAME}_fuzzer
 *
 */
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>

/* DEPENDENCIES HERE */

#define FUZZER_BUF 1024 * 1024

static uint8_t fuzzBuffer[FUZZER_BUF];

int main(int argc, char** argv) 
{
    ssize_t read_bytes = read(stdin, fuzzBuffer, FUZZER_BUF);

    // instantiate appropriate data structures here
    csh handle;
    cs_insn *insn;

    size_t count;

    // setup and initialization calls

    // free memory and close file handles
    cs_close(&handle);
}