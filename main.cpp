#include <sys/mman.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <limits.h>
#include <stdio.h>
#include <sys/syscall.h>   /* For SYS_<x> definitions */

/* TODO -- IMPROVEMENT NOTES

- assemble linked list / hash table with mmap, resized with mremap;
- consider relative indexes (&baseMapAddr[index]) for memory access;
- keep only data on memory_area;
- add 4-byte offset before/after allocations;
- each malloc/free checks canary from previously allocated block and/or currently freed one
  in case it doesn't match, abort;
- also fflush stdout?
*/


extern "C"
{
    void abort(void);
    void __libc_free(void *);
}

#define DEF_AREA_SIZE   (1<<26)

#define DEF_LIST_NUMB   (1<<7)
#define DEF_CTRL_NUMB   (1<<26)

#define likely(x)       __builtin_expect((x),1)
#define unlikely(x)     __builtin_expect((x),0)

#define SLOT_SIZE       512

#define MIN_VALUE(a,b)  ((a) < (b) ? (a) : (b))
#define MAX_VALUE(a,b)  ((a) > (b) ? (a) : (b))

#define FLAG_INUSE      0x80000000

#define SIZE_VALUE(x)   (x & 0x7fffffff)
#define SIZE_ROUND(x)   (((x + SLOT_SIZE - 1) >> 9) << 9)
#define SIZE_OFFSET     (sizeof(unsigned int) << 3)

#define ALIGN_PTR(x)    ((unsigned char *)((((unsigned long)x) >> 3) << 3))

#define CTRL_POS(a,p)   (((p) >> 9) + ((a) * (DEF_AREA_SIZE >> 9)))

#define DEFAULT_AREA    (DEF_LIST_NUMB)

struct memory_area
{
    unsigned char *               base;
    unsigned int                  size;

    pthread_mutex_t               lock;

    unsigned char * volatile      curr;
    volatile unsigned int         busy;
    volatile unsigned int         last;

    void * volatile               last_ptr;
    volatile unsigned int         last_len;
};

struct memory_list
{
    struct memory_area *   base;
    unsigned int           size;
};

struct memory_ctrl
{
    volatile unsigned int *       base;
    unsigned int                  size;
};

#define scoped_context \
    for(bool _make_context##__LINE__ = true; _make_context##__LINE__; _make_context##__LINE__ = false)

struct scoped_mutex
{
    scoped_mutex(pthread_mutex_t * mutex)
    : _mutex(mutex)
    {
        if (_mutex)
        {
            pthread_mutex_lock(_mutex);
        }
    };

    ~scoped_mutex()
    {
        if (_mutex)
        {
            pthread_mutex_unlock(_mutex);
        }
    }

    void unlock()
    {
        if (_mutex)
        {
            pthread_mutex_unlock(_mutex);
            _mutex = NULL;
        }
    }

    pthread_mutex_t * _mutex;
};

static struct memory_list list_base = { NULL, 0 };
static struct memory_ctrl ctrl_base = { NULL, 0 };

static char iobuffer[1024];

static void list_create()
{
    const unsigned int size = DEF_LIST_NUMB * sizeof(struct memory_area);

    list_base.base = (struct memory_area *)mmap(NULL, size, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0);
    list_base.size = DEF_LIST_NUMB;

    if (list_base.base == (void*)-1)
    {
#if defined(MEMDBG_VERBOSE) || defined(MEMDBG_DEBUG)
        fflush(stderr);
#endif
        abort();
    }
}

static void ctrl_create()
{
    const unsigned int size = DEF_CTRL_NUMB * sizeof(unsigned int);

    ctrl_base.base = (unsigned int *)mmap(NULL, size, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0);
    ctrl_base.size = DEF_CTRL_NUMB;

    if (ctrl_base.base == (void*)-1)
    {
#if defined(MEMDBG_VERBOSE) || defined(MEMDBG_DEBUG)
        fflush(stderr);
#endif
        abort();
    }
}

static void area_create()
{
    for (unsigned int i = 0; i < list_base.size; ++i)
    {
        void * const ret = sbrk( DEF_AREA_SIZE );

        if (!ret)
        {
#if defined(MEMDBG_VERBOSE) || defined(MEMDBG_DEBUG)
            fflush(stderr);
#endif
            abort();
        }

        list_base.base[ i ].base = (unsigned char *)ret;
        list_base.base[ i ].size = DEF_AREA_SIZE;

        pthread_mutex_init(&list_base.base[ i ].lock, NULL);

        list_base.base[ i ].curr = (unsigned char *)ret;
        list_base.base[ i ].busy = 0;
        list_base.base[ i ].last = 0;

        list_base.base[ i ].last_ptr = NULL;
        list_base.base[ i ].last_len = 0;
    }
}

static int              allocator_initialized = 0;
static pthread_mutex_t  allocator_mutex = PTHREAD_MUTEX_INITIALIZER;

static void allocator_init()
{
    scoped_mutex mutex(&allocator_mutex);

    if (allocator_initialized == 1)
        return;

    setbuffer(stderr, iobuffer, sizeof(iobuffer));

    ctrl_create();
    list_create();
    area_create();

    allocator_initialized = 1;
}

static void allocator_fini()
{
    munmap(list_base.base, list_base.size * sizeof(struct memory_area));
    munmap((void*)ctrl_base.base, ctrl_base.size * sizeof(unsigned int));
}

int memcheck(const unsigned char * vptr, size_t size, const unsigned char c)
{
    if (ALIGN_PTR(vptr) == vptr)
    {
#ifdef __x86_64__
        const int loops = (size >> 3);
        unsigned long cs = c | ((unsigned long)c << 8) | ((unsigned long)c << 16) | ((unsigned long)c << 24) |
            ((unsigned long)c << 32) | ((unsigned long)c << 40) | ((unsigned long)c << 48) | ((unsigned long)c << 56);
#else
        const int loops = (size >> 2);
        unsigned long cs = c | ((unsigned long)c << 8) | ((unsigned long)c << 16) | ((unsigned long)c << 24);
#endif

        for (unsigned int loop = 0; loop < loops; ++loop)
            if (cs != ((unsigned long *)vptr)[loop])
                return 0;

        size -= loops * sizeof(unsigned long);
        vptr += loops * sizeof(unsigned long);
    }

    while (size--)
    {
        if (*vptr++ != c)
            return 0;
    }

    return 1;
};

void check_boundaries(void * ptr, int size)
{
    const size_t real_size = MAX_VALUE(SIZE_ROUND(size + SIZE_OFFSET), SLOT_SIZE);

    const unsigned char * const data_ptr = (unsigned char *)ptr;
    const unsigned char * const base_ptr = (unsigned char *)((unsigned long)data_ptr & (~0x01ff));

    if (!memcheck(base_ptr, data_ptr - base_ptr, (unsigned char)0xff))
    {
#if defined(MEMDBG_VERBOSE) || defined(MEMDBG_DEBUG)
        fflush(stderr);
#endif
        abort();
    }

    if (!memcheck(&data_ptr[size], &base_ptr[real_size] - &data_ptr[size], (unsigned char)0xff))
    {
#if defined(MEMDBG_VERBOSE) || defined(MEMDBG_DEBUG)
        fflush(stderr);
#endif
        abort();
    }
}

static unsigned char * search_free_memory(const size_t size, const size_t real_size, const int clear, const int lock, const unsigned int area)
{
    scoped_mutex mutex(lock ? &list_base.base[area].lock : NULL);

    const unsigned int    area_size = list_base.base[area].size;
    const unsigned int    area_busy = list_base.base[area].busy;

    /* sorry, area is full! */
    if (area_size == area_busy)
        return NULL;

    unsigned char * const area_base = list_base.base[ area ].base;
    const unsigned int    area_last = list_base.base[ area ].last;

    const unsigned int begn = area * (DEF_AREA_SIZE >> 9);
    const unsigned int ende = begn + (DEF_AREA_SIZE >> 9);

    unsigned int slot_size = 0u;

    unsigned int slot_numb = DEF_CTRL_NUMB;
    unsigned int slot_base = DEF_CTRL_NUMB;

    for (unsigned int i = begn + area_last; i < ende; )
    {
        const unsigned int slot_data = ctrl_base.base[i];

        slot_size = SIZE_VALUE(slot_data);

        const size_t slot_real_size = MAX_VALUE(SIZE_ROUND(slot_size + SIZE_OFFSET), SLOT_SIZE);

        if (slot_data & FLAG_INUSE)
        {
            slot_base = DEF_CTRL_NUMB;
            i += slot_real_size >> 9;
            continue;
        }

        if (real_size > slot_real_size)
        {
            if (slot_base == DEF_CTRL_NUMB)
            {
                slot_base = i;
                i += slot_real_size >> 9;
                continue;
            }

            const unsigned int slot_avail_size = MAX_VALUE(i - slot_base, 0) * SLOT_SIZE;

            if (slot_avail_size >= real_size)
            {
                if (real_size < slot_avail_size)
                {
                    const unsigned int next_slot_numb = slot_base + (real_size >> 9);
                    const unsigned int next_slot_size = slot_avail_size - real_size - SIZE_OFFSET;

#ifdef MEMDBG_DEBUG
                    const unsigned int old_slot_data = ctrl_base.base[ next_slot_numb ];
#endif
                    ctrl_base.base[ next_slot_numb ] = next_slot_size;

#ifdef MEMDBG_DEBUG
                    fprintf(stderr, "+ slot %d area %d merged free (0x%x -> 0x%x)\n", next_slot_numb, area, old_slot_data, next_slot_size);
#endif
                }

                slot_numb = slot_base;
                break;
            }

            i += slot_real_size >> 9;
            continue;
        }

        if (real_size < slot_real_size)
        {
            const unsigned int next_slot_numb = i + (real_size >> 9);
            const unsigned int next_slot_size = slot_real_size - real_size - SIZE_OFFSET;

#ifdef MEMDBG_DEBUG
            const unsigned int old_slot_data = ctrl_base.base[ next_slot_numb ];
#endif
            ctrl_base.base[ next_slot_numb ] = next_slot_size;

#ifdef MEMDBG_DEBUG
            fprintf(stderr, "+ slot %d area %d free (0x%x -> 0x%x)\n", next_slot_numb, area, old_slot_data, next_slot_size);
#endif
        }

        slot_numb = i;
        break;
    }

    if (slot_numb == DEF_CTRL_NUMB)
    {
        slot_base = DEF_CTRL_NUMB;

        for (unsigned int i = begn; i < begn + area_last; )
        {
            const unsigned int slot_data = ctrl_base.base[i];

            slot_size = SIZE_VALUE(ctrl_base.base[i]);

            const size_t slot_real_size = MAX_VALUE(SIZE_ROUND(slot_size + SIZE_OFFSET), SLOT_SIZE);

            if (slot_data & FLAG_INUSE)
            {
                slot_base = DEF_CTRL_NUMB;
                i += slot_real_size >> 9;
                continue;
            }

            if (real_size > slot_real_size)
            {
                if (slot_base == DEF_CTRL_NUMB)
                {
                    slot_base = i;
                    i += slot_real_size >> 9;
                    continue;
                }

                const unsigned int slot_avail_size = MAX_VALUE(i - slot_base, 0) * SLOT_SIZE;

                if (slot_avail_size >= real_size)
                {
                    if (real_size < slot_avail_size)
                    {
                        const unsigned int next_slot_numb = slot_base + (real_size >> 9);
                        const unsigned int next_slot_size = slot_avail_size - real_size - SIZE_OFFSET;

#ifdef MEMDBG_DEBUG
                        const unsigned int old_slot_data = ctrl_base.base[ next_slot_numb ];
#endif
                        ctrl_base.base[ next_slot_numb ] = next_slot_size;

#ifdef MEMDBG_DEBUG
                        fprintf(stderr, "+ slot %d area %d merged free (0x%x -> 0x%x)\n", next_slot_numb, area, old_slot_data, next_slot_size);
#endif
                    }

                    slot_numb = slot_base;
                    break;
                }

                i += slot_real_size >> 9;
                continue;
            }

            if (real_size < slot_real_size)
            {
                const unsigned int next_slot_numb = i + (real_size >> 9);
                const unsigned int next_slot_size = slot_real_size - real_size - SIZE_OFFSET;

#ifdef MEMDBG_DEBUG
                const unsigned int old_slot_data = ctrl_base.base[ next_slot_numb ];
#endif

                ctrl_base.base[ next_slot_numb ] = next_slot_size;

#ifdef MEMDBG_DEBUG
                fprintf(stderr, "+ slot %d area %d free (0x%x -> 0x%x)\n", next_slot_numb, area, old_slot_data, next_slot_size);
#endif
            }

            slot_numb = i;
            break;
        }
    }

    if (slot_numb == DEF_CTRL_NUMB)
        return NULL;

    list_base.base[ area ].last  = slot_numb - begn;
    list_base.base[ area ].busy += real_size;

    unsigned char * const area_curr = &area_base[ SLOT_SIZE * (slot_numb - begn) ];

    unsigned char * const data_base = ALIGN_PTR(&area_curr[ (real_size - size) >> 1 ]);
    unsigned char * const data_ende = data_base + size;

    unsigned char * const ende_curr = &area_curr[ real_size ];

#ifdef MEMDBG_DEBUG
    const unsigned int old_slot_data = ctrl_base.base[ slot_numb ];
#endif

    ctrl_base.base[ slot_numb ] = (unsigned int)(FLAG_INUSE | size);

#ifdef MEMDBG_DEBUG
    fprintf(stderr, "+ reusing %p on slot %d [%d] area %d (0x%x -> 0x%x)\n", data_base, slot_numb, real_size >> 9, area,
        old_slot_data, ctrl_base.base[ slot_numb ]);
#endif

    memset(area_curr, 0xff, data_base - area_curr);

    if (clear)
        memset(data_base, 0x00, data_ende - data_base);

    memset(data_ende, 0xff, ende_curr - data_ende);

    return data_base;
}

static int search_memory_area(unsigned char *addr, const int hint, const int lock)
{
    for (unsigned int area = hint; area < DEF_LIST_NUMB; ++area)
    {
        scoped_mutex mutex(lock ? &list_base.base[area].lock : NULL);

        unsigned char * const area_base = list_base.base[area].base;
        unsigned char * const area_curr = list_base.base[area].curr;
        const unsigned int    area_size = list_base.base[area].size;

        if (area_curr == area_base)
            continue;

        if (addr >= area_base && addr < &area_base[area_size])
            return area;
    }

    for (unsigned int area = 0; area < hint; ++area)
    {
        scoped_mutex mutex(lock ? &list_base.base[area].lock : NULL);

        unsigned char * const area_base = list_base.base[area].base;
        unsigned char * const area_curr = list_base.base[area].curr;
        const unsigned int    area_size = list_base.base[area].size;

        if (area_curr == area_base)
            continue;

        if (addr >= area_base && addr < &area_base[area_size])
            return area;
    }

    return -1;
}

static unsigned int get_slot_data(unsigned char *addr, const int hint, const int lock)
{
    const int area = search_memory_area(addr, hint, 0);

    if (area < 0)
        return 0;

    scoped_context
    {
        scoped_mutex mutex(lock ? &list_base.base[area].lock : NULL);

        const unsigned int slot_data = ctrl_base.base[CTRL_POS(area, addr - list_base.base[area].base)];

        return slot_data;
    }

    return 0; // never reached
}

static int get_area_hint()
{
    return syscall(SYS_gettid) % DEF_LIST_NUMB;
}

static unsigned char * allocate_memory_from_area(const size_t size, const int clear, const int lock, const int suggested_area);

static unsigned char * exaustive_search_for_memory(const size_t size, const size_t real_size, const int clear, const int last_area)
{
    for (unsigned int i = last_area+1; i < DEF_LIST_NUMB; ++i)
    {
       unsigned char * data_base = allocate_memory_from_area(size, clear, 1, i);

       if (data_base)
           return data_base;

       data_base = search_free_memory(size, real_size, clear, 1, i);

       if (data_base)
           return data_base;
    }

    /* try from other areas (below) */
    for (unsigned int i = 0; i < last_area; ++i)
    {
        unsigned char * data_base = allocate_memory_from_area(size, clear, 1, i);

        if (data_base)
            return data_base;

        data_base = search_free_memory(size, real_size, clear, 1, i);

        if (data_base)
            return data_base;
    }

    return NULL;
}

static unsigned char * allocate_memory_from_area(const size_t size, const int clear, const int lock, const int suggested_area)
{
    if (suggested_area == -1) return NULL;

    const size_t real_size = MAX_VALUE(SIZE_ROUND(size + SIZE_OFFSET), SLOT_SIZE);

    /* standard: larger values from higher areas */
    const unsigned int area = (suggested_area == DEFAULT_AREA ? get_area_hint() : suggested_area);

    if (area > DEF_LIST_NUMB)
        return NULL;

    scoped_mutex mutex(lock ? &list_base.base[area].lock : NULL);

    const unsigned int area_size = list_base.base[area].size;

    unsigned char * const area_base = list_base.base[area].base;
    unsigned char * const area_curr = list_base.base[area].curr;

    unsigned char * const ende_curr = &area_curr[real_size];

    if (ende_curr > &area_base[area_size])
    {
        if (suggested_area != DEFAULT_AREA)
            return NULL;

        scoped_context
        {
            /* try to search our own area for freed space */
            unsigned char * const data_base = search_free_memory(size, real_size, clear, 0, area);

            if (data_base)
                return data_base;
        }

        mutex.unlock();

        return exaustive_search_for_memory(size, real_size, clear, area);
    }

    list_base.base[area].curr = ende_curr;
    list_base.base[area].busy += real_size;

    const unsigned int slot_nr = CTRL_POS(area, area_curr - area_base);
    ctrl_base.base[slot_nr] = (unsigned int)(FLAG_INUSE | size);

    unsigned char * const data_base = ALIGN_PTR(&area_curr[ (real_size - size) >> 1 ]);
    unsigned char * const data_ende = data_base + size;

    memset(area_curr, 0xff, data_base - area_curr);

    if (clear)
        memset(data_base, 0x00, data_ende - data_base);

    memset(data_ende, 0xff, ende_curr - data_ende);

    if (list_base.base[area].last_ptr)
    {
        check_boundaries(list_base.base[area].last_ptr, list_base.base[area].last_len);

        list_base.base[area].last_ptr = data_base;
        list_base.base[area].last_len = size;
    }

    mutex.unlock();

#ifdef MEMDBG_DEBUG
    fprintf(stderr, "+ alloc %p on slot %d (area %d)\n", data_base, slot_nr, area);
#endif

    return data_base;
}

static unsigned char * allocate_memory(const size_t size, const int clear, const int lock)
{
    if (unlikely(!allocator_initialized))
        allocator_init();

    return allocate_memory_from_area(size, clear, 1, DEFAULT_AREA);
}

static int deallocate_memory(unsigned char * addr, const int lock)
{
    if (unlikely(!allocator_initialized))
        allocator_init();

    const int area = search_memory_area(addr, get_area_hint(), 0);

    if (area == -1)
        return 0;

    scoped_mutex mutex(lock ? &list_base.base[area].lock : NULL);

    unsigned char * const area_base = list_base.base[area].base;

    const unsigned int slot_numb = CTRL_POS(area, addr - area_base);
    const unsigned int slot_data = ctrl_base.base[slot_numb];
    const unsigned int slot_size = SIZE_VALUE(slot_data);

    /* freeing already free pointer */
    if (slot_data == slot_size)
    {
#if defined(MEMDBG_VERBOSE) || defined(MEMDBG_DEBUG)
        fflush(stderr);
#endif
        abort();
    }

    const unsigned int slot_real_size = MAX_VALUE(SIZE_ROUND(slot_size + SIZE_OFFSET), SLOT_SIZE);

    list_base.base[area].busy = MAX_VALUE(list_base.base[ area ].busy - slot_real_size, 0);

    ctrl_base.base[slot_numb] = slot_real_size - SIZE_OFFSET;

    check_boundaries(addr, slot_size);

    if (list_base.base[area].last_ptr == addr)
    {
        list_base.base[area].last_ptr = NULL;
        list_base.base[area].last_len = 0u;
    }

    if (((unsigned long)addr & 0xe00) == 0) /* page aligned? (9 LSB are irrelevant for us) */
    {
        unsigned char * const area_curr = list_base.base[area].curr;

        const unsigned int slot_ende = (area + 1) * ((area_curr - area_base) >> 9);

        unsigned int slot_last = slot_numb;

#ifdef MEMDBG_DEBUG_ADVISE
        fprintf(stderr, "+ checking %p [%d]: ", addr, slot_numb);
#endif

        for (unsigned int i = slot_numb; i < slot_ende; )
        {
            const unsigned int i_data = ctrl_base.base[i];
            const unsigned int i_size = SIZE_VALUE(i_data);

#ifdef MEMDBG_DEBUG_ADVISE
            fprintf(stderr, "%d ", i);
#endif

            if (i_data & FLAG_INUSE) break;

            i += MAX_VALUE(((i_size + SLOT_SIZE - 1) >> 9), 1);

            slot_last = i-1;
        }

        const unsigned int amount = ((slot_last - slot_numb) & (~0x7)) * SLOT_SIZE;

#ifdef MEMDBG_DEBUG_ADVISE
        fprintf(stderr, " resulted %d.\n", amount);
#endif

        if (amount)
        {
            unsigned char * const addr_page = (unsigned char *)((unsigned long)addr & (~0x1ff));

#ifdef MEMDBG_DEBUG
            fprintf(stderr, "+ advising freed: %p size %d\n", addr_page, amount);
#endif
            madvise(addr_page, amount, MADV_DONTNEED);
        }
    }

    mutex.unlock();

#ifdef MEMDBG_DEBUG
    fprintf(stderr, "+ freeing %p on slot %d (%x)\n", addr, slot_numb, slot_data);
#endif

    return 1;
}

/*************************************************************************************************************/

extern "C"
{

void * malloc(size_t size)
{
    void * const retr = allocate_memory(size, 0, 1);

#ifdef MEMDBG_VERBOSE
    fprintf(stderr, "[%06d] malloc(%d) = %p\n", syscall(SYS_gettid), size, retr);
#endif

#if defined(MEMDBG_VERBOSE) || defined(MEMDBG_DEBUG)
    fflush(stderr);
#endif

    return retr;
}

void * calloc(size_t nm, size_t sz)
{
    const size_t size = nm * sz;

    void * const retr = allocate_memory(size, 1, 1);

#ifdef MEMDBG_VERBOSE
    fprintf(stderr, "[%06d] calloc(%d,%d) [%d] = %p\n", syscall(SYS_gettid), nm, sz, size, retr);
#endif

#if defined(MEMDBG_VERBOSE) || defined(MEMDBG_DEBUG)
    fflush(stderr);
#endif

    return retr;
}

void * realloc(void * ptr, size_t size)
{
    if (ptr && !size)
    {
        deallocate_memory((unsigned char *)ptr, 1);
        return NULL;
    }

    void * const ret = allocate_memory(size, 0, 1);

    if (!ptr)
        return ret;

    const int len = SIZE_VALUE(get_slot_data((unsigned char *)ptr, get_area_hint(), 0));

    if (!len)
    {
#if defined(MEMDBG_VERBOSE) || defined(MEMDBG_DEBUG)
        fflush(stderr);
#endif
        abort();
    }

    memcpy(ret, ptr, size); // len);

    if (!deallocate_memory((unsigned char *)ptr, 0))
    {
        fprintf(stderr, "unable to free %p, passing to glibc...\n", ptr);
        fflush(stderr);
        __libc_free(ptr);
    }

#ifdef MEMDBG_VERBOSE
    fprintf(stderr, "[%06d] realloc(%p,%d) = %p\n", syscall(SYS_gettid), ptr, size, ret);
#endif

#if defined(MEMDBG_VERBOSE) || defined(MEMDBG_DEBUG)
    fflush(stderr);
#endif

    return ret;
}

void free(void * ptr)
{
    if (!ptr) return;

    if (!deallocate_memory((unsigned char *)ptr, 1))
    {
        fprintf(stderr, "unable to free %p, passing to glibc...\n", ptr);
        __libc_free(ptr);
    }
#ifdef MEMDBG_VERBOSE
    else
    {
        fprintf(stderr, "[%06d] free(%p)\n", syscall(SYS_gettid), ptr);
    }
#endif

#if defined(MEMDBG_VERBOSE) || defined(MEMDBG_DEBUG)
    fflush(stderr);
#endif
}

int posix_memalign(void **memptr, size_t alignment, size_t size)
{
    if (alignment > 512)
    {
#if defined(MEMDBG_VERBOSE) || defined(MEMDBG_DEBUG)
        fflush(stderr);
#endif
        abort();
    }

    *memptr = allocate_memory(size, 0, 1);

#ifdef MEMDBG_VERBOSE
    fprintf(stderr, "[%06d] posix_memalign(%p,%d,%d)\n", syscall(SYS_gettid), *memptr, alignment, size);
#endif

#if defined(MEMDBG_VERBOSE) || defined(MEMDBG_DEBUG)
    fflush(stderr);
#endif

    return 0;
}

void * memalign(size_t alignment, size_t size)
{
    if (alignment > 512)
    {
#if defined(MEMDBG_VERBOSE) || defined(MEMDBG_DEBUG)
        fflush(stderr);
#endif
        abort();
    }

    void * const retr = allocate_memory(size, 0, 1);

#ifdef MEMDBG_VERBOSE
    fprintf(stderr, "[%06d] memalign(%d,%d) = %p\n", syscall(SYS_gettid), alignment, size, retr);
#endif

#if defined(MEMDBG_VERBOSE) || defined(MEMDBG_DEBUG)
    fflush(stderr);
#endif

    return retr;
}

void * valloc(size_t size)
{
    void * const retr = allocate_memory(size, 0, 1);
#ifdef MEMDBG_VERBOSE
    fprintf(stderr, "[%06d] valloc(%d) = %p\n", syscall(SYS_gettid), size, retr);
#endif

#if defined(MEMDBG_VERBOSE) || defined(MEMDBG_DEBUG)
    fflush(stderr);
#endif

    return retr;
}

char * strdup(const char * s)
{
    const unsigned int len = strlen(s)+1;

    unsigned char * const ret = allocate_memory(len, 0, 1);

    memcpy(ret, s, len);
    ret[len] = 0;

#ifdef MEMDBG_VERBOSE
    fprintf(stderr, "[%06d] strdup(%p) [%d] = %p\n", syscall(SYS_gettid), s, len, ret);
#endif

#if defined(MEMDBG_VERBOSE) || defined(MEMDBG_DEBUG)
    fflush(stderr);
#endif

    return (char *)ret;
}

char * strndup(const char * s, size_t n)
{
    const unsigned int len = strlen(s)+1;

    unsigned char * const ret = allocate_memory(len, 0, 1);

    const unsigned int n2 = MIN_VALUE(len, n);

    memcpy(ret, s, n2);
    ret[n2] = 0;

#ifdef MEMDBG_VERBOSE
    fprintf(stderr, "[%06d] strndup(%p,%d) [%d] = %p\n", syscall(SYS_gettid), s, n, len, ret);
#endif

#if defined(MEMDBG_VERBOSE) || defined(MEMDBG_DEBUG)
    fflush(stderr);
#endif

    return (char *)ret;
}

}