#ifndef PQDTLS_DEBUG_H
#define PQDTLS_DEBUG_H

#ifdef DEBUG
#define DEBUG_TEST 1
#else
#define DEBUG_TEST 0
#endif

#define dprint(fmt, ...) \
        do { if (DEBUG_TEST) fprintf(stderr, "%s:%d:%s(): " fmt "\n", __FILE__, \
                                __LINE__, __func__, ##__VA_ARGS__); } while (0)

#define fdprint(file, fmt, ...) \
        do { if (DEBUG_TEST) fprintf(file, "%s:%d:%s(): " fmt "\n", __FILE__, \
                                __LINE__, __func__, ##__VA_ARGS__); } while (0)

#endif // PQDTLS_DEBUG_H