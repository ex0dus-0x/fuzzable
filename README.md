# fuzzable

Automated Excavation of Fuzzable API Routines

## Signatures

`RETTYPE funcName(..., char *buffer, size_t len, ...);`
`RETTYPE funcName(FILE *fd);`

## Ignores

* __asan
* __afl
