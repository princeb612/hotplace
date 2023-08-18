/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#if defined __GNUC__
#if (((__GNUC__ == 4) && (__GNUC_MINOR__ >= 1)) || (__GNUC__ > 4))
// gcc-4.1
// atomic.h
// __sync_fetch_and_add
// __sync_sub_and_fetch
#else

/* #define PTHREAD_MUTEX_INITIALIZER {0, 0, 0, PTHREAD_MUTEX_TIMED_NP, __LOCK_INITIALIZER} */
static pthread_mutex_t sync_lock = PTHREAD_MUTEX_INITIALIZER;

int __sync_fetch_and_add (int* ptr, int add)
{
    int i = 0;
    int ret;

    i = pthread_mutex_lock (&sync_lock);

    ret = *ptr;
    *ptr += add;

    i = pthread_mutex_unlock (&sync_lock);

    return ret;
}

int __sync_sub_and_fetch (int* ptr, int sub)
{
    int i = 0;
    int ret;

    i = pthread_mutex_lock (&sync_lock);

    ret = *ptr;
    *ptr -= sub;

    i = pthread_mutex_unlock (&sync_lock);

    return ret;
}
#endif
#endif
