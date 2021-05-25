/* 
 * linux_harness.cpp
 *
 */

#include <dlfcn.h>
#include <alloca.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// int64_t BNCreateFileMetadata();
typedef int64_t (*bn_file_metadata_t)();

// int64_t BNCreateBinaryDataViewFromBuffer(int64_t* dataview, int64_t* buf);
typedef int64_t (*bn_dv_buffer_t)(int64_t*, int64_t*);

// void* BNCreateBinaryDataViewFromFilename(int64_t *dataview, char *filename);
typedef void* (*bn_dv_filename_t)(int64_t*, char*);


// points to shared object being preloaded
void* core_handle = NULL;
void* ui_handle = NULL;


void CloseLibrary(void)
{
    if (core_handle)
        dlclose(core_handle);
    core_handle = NULL;
}


#ifdef LIBFUZZER
extern "C"
#endif
int LoadLibrary(void)
{
    core_handle = dlopen("/opt/binaryninja/libbinaryninjacore.so.1", RTLD_LAZY);
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

    // create new file metadata core_handle
    bn_file_metadata_t BNCreateFileMetadata =
        (bn_file_metadata_t) dlsym(core_handle, "BNCreateFileMetadata");
    metadata = BNCreateFileMetadata();

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

    // get sym to buffer parser
    bn_dv_buffer_t BNCreateBinaryDataViewFromBuffer = 
        (bn_dv_buffer_t) dlsym(core_handle, "BNCreateBinaryDataViewFromBuffer");

    int64_t res = BNCreateBinaryDataViewFromBuffer(&metadata, buf);
#else
    if (argc != 2)
        return -1;
    char *filepath = argv[1];

    // get sym to filename parser
    bn_dv_filename_t BNCreateBinaryDataViewFromFilename =
        (bn_dv_filename_t) dlsym(core_handle, "BNCreateBinaryDataViewFromFilename");

    printf("Starting file fuzzing at %p\n", BNCreateBinaryDataViewFromFilename);
    void *res = BNCreateBinaryDataViewFromFilename(&metadata, filepath);
#endif

    return 0;
}
