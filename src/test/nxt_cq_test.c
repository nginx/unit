
/*
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>
#include <math.h>
#include <inttypes.h>

#ifndef NXT_NCQ_TEST
#define NXT_NCQ_TEST          1
#endif

#define NXT_QTEST_USE_THREAD  0

#if NXT_NCQ_TEST
#include <nxt_nncq.h>
#else
#include <nxt_nvbcq.h>
#endif


#define MAX_ITER   20
#define STAT_ITER  5
#define MIN_COV    0.02

extern char  **environ;
static uintptr_t nops = 10000000;

static uintptr_t nprocs_enq     = 0;
static uintptr_t nprocs_deq     = 0;
static uintptr_t nprocs_wenq    = 0;
static uintptr_t nprocs_wdeq    = 0;
static uintptr_t nprocs_enq_deq = 0;
static uintptr_t nprocs_cas     = 0;
static uintptr_t nprocs_faa     = 0;

static uintptr_t nprocs = 1;


static size_t
elapsed_time(size_t us)
{
  struct timeval t;

  gettimeofday(&t, NULL);

  return t.tv_sec * 1000000 + t.tv_usec - us;
}


static double
mean(const double *times, int n)
{
    int     i;
    double  sum;

    sum = 0;

    for (i = 0; i < n; i++) {
        sum += times[i];
    }

    return sum / n;
}


static double
cov(const double *times, double mean, int n)
{
    int     i;
    double  variance;

    variance = 0;

    for (i = 0; i < n; i++) {
        variance += (times[i] - mean) * (times[i] - mean);
    }

    variance /= n;

    return sqrt(variance) / mean;
}

typedef struct {
#if NXT_NCQ_TEST
    nxt_nncq_t   free_queue;
    nxt_nncq_t   active_queue;
#else
    nxt_nvbcq_t  free_queue;
    nxt_nvbcq_t  active_queue;
#endif
    uint32_t     counter;
} nxt_cq_t;


static nxt_cq_t  *pgq;


#if NXT_NCQ_TEST
#define nxt_cq_enqueue  nxt_nncq_enqueue
#define nxt_cq_dequeue  nxt_nncq_dequeue
#define nxt_cq_empty    nxt_nncq_empty
#define nxt_cq_init     nxt_nncq_init
#define NXT_CQ_SIZE     NXT_NNCQ_SIZE
#else
#define nxt_cq_enqueue  nxt_nvbcq_enqueue
#define nxt_cq_dequeue  nxt_nvbcq_dequeue
#define nxt_cq_empty    nxt_nvbcq_empty
#define nxt_cq_init     nxt_nvbcq_init
#define NXT_CQ_SIZE     NXT_NVBCQ_SIZE
#endif

typedef struct {
    int                  id;
    uint64_t             enq;
    uint64_t             deq;
    uint64_t             wait_enq;
    uint64_t             wait_deq;
    uint64_t             own_res;
    uint64_t             cas;
    uint64_t             faa;

#if NXT_QTEST_USE_THREAD
    nxt_thread_handle_t  handle;
#else
    nxt_pid_t            pid;
    int status;
#endif
} nxt_worker_info_t;


static void
cas_worker(void *p)
{
    nxt_cq_t           *q;
    uint32_t           c;
    uintptr_t          i;
    nxt_worker_info_t  *wi;

    q = pgq;
    wi = p;

    for (i = 0; i < nops / nprocs_cas; i++) {
        c = q->counter;

        if (nxt_atomic_cmp_set(&q->counter, c, c + 1)) {
            ++wi->cas;
        }
    }
}


static void
faa_worker(void *p)
{
    nxt_cq_t           *q;
    uintptr_t          i;
    nxt_worker_info_t  *wi;

    q = pgq;
    wi = p;

    for (i = 0; i < nops / nprocs_faa; i++) {
        nxt_atomic_fetch_add(&q->counter, 1);
        wi->faa++;
    }
}


static void
enq_deq_worker(void *p)
{
    nxt_cq_t           *q;
    uintptr_t          i, v;
    nxt_worker_info_t  *wi;

    q = pgq;
    wi = p;

    for (i = 0; i < nops / nprocs_enq_deq; i++) {
        v = nxt_cq_dequeue(&q->free_queue);

        if (v != nxt_cq_empty(&q->free_queue)) {
            nxt_cq_enqueue(&q->active_queue, wi->id);
            wi->enq++;
        }

        v = nxt_cq_dequeue(&q->active_queue);

        if (v != nxt_cq_empty(&q->active_queue)) {
            nxt_cq_enqueue(&q->free_queue, v);
            wi->deq++;

            if ((int) v == wi->id) {
                wi->own_res++;
            }
        }
    }
}


static void
enq_worker(void *p)
{
    nxt_cq_t           *q;
    uintptr_t          i, v;
    nxt_worker_info_t  *wi;

    q = pgq;
    wi = p;

    for (i = 0; i < nops / nprocs_enq; i++) {
        v = nxt_cq_dequeue(&q->free_queue);

        if (v != nxt_cq_empty(&q->free_queue)) {
            nxt_cq_enqueue(&q->active_queue, v);
            wi->enq++;
        }
    }
}


static void
deq_worker(void *p)
{
    nxt_cq_t           *q;
    uintptr_t          i, v;
    nxt_worker_info_t  *wi;

    q = pgq;
    wi = p;

    for (i = 0; i < nops / nprocs_deq; i++) {
        v = nxt_cq_dequeue(&q->active_queue);

        if (v != nxt_cq_empty(&q->active_queue)) {
            nxt_cq_enqueue(&q->free_queue, v);
            ++wi->deq;
        }
    }
}


static void
wenq_worker(void *p)
{
    nxt_cq_t           *q;
    uintptr_t          i, v;
    nxt_worker_info_t  *wi;

    q = pgq;
    wi = p;

    for (i = 0; i < nops / nprocs_wenq; i++) {

        do {
            wi->wait_enq++;
            v = nxt_cq_dequeue(&q->free_queue);
        } while (v == nxt_cq_empty(&q->free_queue));

        nxt_cq_enqueue(&q->active_queue, v);

        wi->enq++;
        wi->wait_enq--;
    }
}


static void
wdeq_worker(void *p)
{
    nxt_cq_t           *q;
    uintptr_t          i, v;
    nxt_worker_info_t  *wi;

    q = pgq;
    wi = p;

    for (i = 0; i < nops / nprocs_wdeq; i++) {

        do {
            wi->wait_deq++;
            v = nxt_cq_dequeue(&q->active_queue);
        } while (v == nxt_cq_empty(&q->active_queue));

        nxt_cq_enqueue(&q->free_queue, v);

        wi->deq++;
        wi->wait_deq--;
    }
}


static nxt_int_t
worker_create(nxt_worker_info_t *wi, int id, nxt_thread_start_t start)
{
    wi->id = id;

#if NXT_QTEST_USE_THREAD
    nxt_thread_link_t  *link;

    link = nxt_zalloc(sizeof(nxt_thread_link_t));

    link->start = start;
    link->work.data = wi;

    return nxt_thread_create(&wi->handle, link);

#else
    pid_t pid = fork();

    if (pid == 0) {
        start(wi);
        exit(0);

    } else {
        wi->pid = pid;
    }

    return NXT_OK;
#endif
}


static void
worker_wait(nxt_worker_info_t *wi)
{
#if NXT_QTEST_USE_THREAD
    pthread_join(wi->handle, NULL);

#else
    waitpid(wi->pid, &wi->status, 0);
#endif
}


int nxt_cdecl
main(int argc, char **argv)
{
    int                i, k, id, verbose, objective, rk;
    char               *a;
    size_t             start, elapsed;
    double             *stats, m, c;
    uint64_t           total_ops;
    uintptr_t          j;
    nxt_task_t         task;
    nxt_thread_t       *thr;
    nxt_worker_info_t  *wi;
    double             times[MAX_ITER], mopsec[MAX_ITER];

    verbose = 0;
    objective = 0;

    for (i = 1; i < argc; i++) {
        a = argv[i];

        if (strcmp(a, "-v") == 0) {
            verbose++;
            continue;
        }

        if (strcmp(a, "-n") == 0 && (i + 1) < argc) {
            nops = atoi(argv[++i]);
            continue;
        }

        if (strcmp(a, "--enq") == 0 && (i + 1) < argc) {
            nprocs_enq = atoi(argv[++i]);
            continue;
        }

        if (strcmp(a, "--deq") == 0 && (i + 1) < argc) {
            nprocs_deq = atoi(argv[++i]);
            continue;
        }

        if (strcmp(a, "--wenq") == 0 && (i + 1) < argc) {
            nprocs_wenq = atoi(argv[++i]);
            continue;
        }

        if (strcmp(a, "--wdeq") == 0 && (i + 1) < argc) {
            nprocs_wdeq = atoi(argv[++i]);
            continue;
        }

        if (strcmp(a, "--ed") == 0 && (i + 1) < argc) {
            nprocs_enq_deq = atoi(argv[++i]);
            continue;
        }

        if (strcmp(a, "--cas") == 0 && (i + 1) < argc) {
            nprocs_cas = atoi(argv[++i]);
            continue;
        }

        if (strcmp(a, "--faa") == 0 && (i + 1) < argc) {
            nprocs_faa = atoi(argv[++i]);
            continue;
        }

        if (strcmp(a, "--obj") == 0 && (i + 1) < argc) {
            objective = atoi(argv[++i]);
            continue;
        }

        printf("unknown option %s", a);

        return 1;
    }

    if (nxt_lib_start("ncq_test", argv, &environ) != NXT_OK) {
        return 1;
    }

    nprocs = nprocs_enq + nprocs_deq + nprocs_wenq + nprocs_wdeq
             + nprocs_enq_deq + nprocs_cas + nprocs_faa;

    if (nprocs == 0) {
        return 0;
    }

    nxt_main_log.level = NXT_LOG_INFO;
    task.log  = &nxt_main_log;

    thr = nxt_thread();
    thr->task = &task;

    pgq = mmap(NULL, sizeof(nxt_cq_t), PROT_READ | PROT_WRITE,
               MAP_ANON | MAP_SHARED, -1, 0);
    if (pgq == MAP_FAILED) {
        return 2;
    }

    nxt_cq_init(&pgq->free_queue);
    nxt_cq_init(&pgq->active_queue);

    for(i = 0; i < NXT_CQ_SIZE; i++) {
        nxt_cq_enqueue(&pgq->free_queue, i);
    }

    if (verbose >= 1) {
        printf("number of workers: %d\n", (int) nprocs);
        printf("number of ops:     %d\n", (int) nops);
    }

    wi = mmap(NULL, nprocs * sizeof(nxt_worker_info_t), PROT_READ | PROT_WRITE,
              MAP_ANON | MAP_SHARED, -1, 0);
    if (wi == MAP_FAILED) {
        return 3;
    }

    for (k = 0; k < MAX_ITER; k++) {
        nxt_memzero(wi, nprocs * sizeof(nxt_worker_info_t));

        nxt_cq_init(&pgq->free_queue);
        nxt_cq_init(&pgq->active_queue);

        for(i = 0; i < NXT_CQ_SIZE; i++) {
            nxt_cq_enqueue(&pgq->free_queue, i);
        }

        start = elapsed_time(0);

        id = 0;

        for (j = 0; j < nprocs_enq; j++, id++) {
            worker_create(wi + id, id, enq_worker);
        }

        for (j = 0; j < nprocs_deq; j++, id++) {
            worker_create(wi + id, id, deq_worker);
        }

        for (j = 0; j < nprocs_wenq; j++, id++) {
            worker_create(wi + id, id, wenq_worker);
        }

        for (j = 0; j < nprocs_wdeq; j++, id++) {
            worker_create(wi + id, id, wdeq_worker);
        }

        for (j = 0; j < nprocs_enq_deq; j++, id++) {
            worker_create(wi + id, id, enq_deq_worker);
        }

        for (j = 0; j < nprocs_cas; j++, id++) {
            worker_create(wi + id, id, cas_worker);
        }

        for (j = 0; j < nprocs_faa; j++, id++) {
            worker_create(wi + id, id, faa_worker);
        }

        for (j = 0; j < nprocs; j++) {
            worker_wait(wi + j);
        }

        elapsed = elapsed_time(start);

        for (j = 1; j < nprocs; j++) {
            wi[0].enq += wi[j].enq;
            wi[0].deq += wi[j].deq;
            wi[0].wait_enq += wi[j].wait_enq;
            wi[0].wait_deq += wi[j].wait_deq;
            wi[0].own_res += wi[j].own_res;
            wi[0].cas += wi[j].cas;
            wi[0].faa += wi[j].faa;
        }

        total_ops = wi[0].enq + wi[0].deq + wi[0].cas + wi[0].faa;

        if (total_ops == 0) {
            total_ops = nops;
        }

        times[k] = elapsed / 1000.0;
        mopsec[k] = (double) total_ops / elapsed;

        if (verbose >= 2) {
            printf("enq        %10"PRIu64"\n", wi[0].enq);
            printf("deq        %10"PRIu64"\n", wi[0].deq);
            printf("wait_enq   %10"PRIu64"\n", wi[0].wait_enq);
            printf("wait_deq   %10"PRIu64"\n", wi[0].wait_deq);
            printf("own_res    %10"PRIu64"\n", wi[0].own_res);
            printf("cas        %10"PRIu64"\n", wi[0].cas);
            printf("faa        %10"PRIu64"\n", wi[0].faa);
            printf("total ops  %10"PRIu64"\n", total_ops);
            printf("Mops/sec   %13.2f\n", mopsec[k]);

            printf("elapsed    %10d us\n", (int) elapsed);
            printf("per op     %10d ns\n", (int) ((1000 * elapsed) / total_ops));
        }

        if (k >= STAT_ITER) {
            stats = (objective == 0) ? times : mopsec;

            m = mean(stats + k - STAT_ITER, STAT_ITER);
            c = cov(stats + k - STAT_ITER, m, STAT_ITER);

            if (verbose >= 1) {
                if (objective == 0) {
                    printf("  #%02d elapsed time: %.2f ms; Mops/sec %.2f; "
                           "mean time %.2f ms; cov %.4f\n",
                           (int) k + 1, times[k], mopsec[k], m, c);

                } else {
                    printf("  #%02d elapsed time: %.2f ms; Mops/sec %.2f; "
                           "mean Mop/sec %.2f; cov %.4f\n",
                           (int) k + 1, times[k], mopsec[k], m, c);
                }
            }

            if (c < MIN_COV) {
                rk = k - STAT_ITER;

                for (i = rk + 1; i <= k; i++) {
                    if (fabs(stats[i] - m) < fabs(stats[rk] - m)) {
                        rk = i;
                    }
                }

                printf("#%d %.2f ms; %.2f\n", rk, times[rk], mopsec[rk]);

                return 0;
            }

        } else {
            if (verbose >= 1) {
                printf("  #%02d elapsed time: %.2f ms; Mops/sec %.2f\n",
                       (int) k + 1, times[k], mopsec[k]);
            }
        }
    }

    return 0;
}
