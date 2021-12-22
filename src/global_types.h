#ifndef GLOBAL_TYPES_H
#define GLOBAL_TYPES_H

#define PATH_LIMIT 260
#define INPUT_LIMIT 2048

#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define MAX(a, b) ((a) < (b) ? (b) : (a))
#define CEIL_TO_NEAREST(a, b) ((((a) + (b) - 1)/(b)) * (b))

typedef unsigned char byte;

typedef unsigned int u32;
typedef unsigned long long u64;
typedef int i32;
typedef long long i64;

#endif //GLOBAL_TYPES_H
