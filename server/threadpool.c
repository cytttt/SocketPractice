#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>

#include "threadpool.h"

typedef enum {
    immediate_shutdown = 1,
    graceful_shutdown  = 2
} threadpool_shutdown_t;


typedef struct {
    void (*function)(void *);
    void *argument;
} threadpool_task_t;

struct threadpool_t {
  pthread_mutex_t lock;
  pthread_cond_t notify;
  pthread_t *threads;
  threadpool_task_t *queue;
  int thread_count;
  int queue_size;
  int head;
  int tail;
  int count;
  int shutdown;
  int started;
};

static void *threadpool_thread(void *threadpool);

int threadpool_free(threadpool_t *pool);

threadpool_t *threadpool_create(int thread_count, int queue_size, int flags)
{
    if(thread_count <= 0 || thread_count > MAX_THREADS || queue_size <= 0 || queue_size > MAX_QUEUE) {
        return NULL;
    }

    threadpool_t *pool;
    int i;

    if((pool = (threadpool_t *)malloc(sizeof(threadpool_t))) == NULL) {
        goto err;
    }

    pool->thread_count = 0;
    pool->queue_size = queue_size;
    pool->head = pool->tail = pool->count = 0;
    pool->shutdown = pool->started = 0;


    pool->threads = (pthread_t *)malloc(sizeof(pthread_t) * thread_count);
    pool->queue = (threadpool_task_t *)malloc
        (sizeof(threadpool_task_t) * queue_size);

    if((pthread_mutex_init(&(pool->lock), NULL) != 0) ||
       (pthread_cond_init(&(pool->notify), NULL) != 0) ||
       (pool->threads == NULL) ||
       (pool->queue == NULL)) {
        goto err;
    }

    for(i = 0; i < thread_count; i++) {
        if(pthread_create(&(pool->threads[i]), NULL,
                          threadpool_thread, (void*)pool) != 0) {
            threadpool_destroy(pool, 0);
            return NULL;
        }
        pool->thread_count++;
        pool->started++;
    }

    return pool;

 err:
    if(pool) {
        threadpool_free(pool);
    }
    return NULL;
}

int threadpool_add(threadpool_t *pool, void (*function)(void *),
                   void *argument, int flags)
{
    int err = 0;
    int next;

    if(pool == NULL || function == NULL) {
        return threadpool_invalid;
    }

    if(pthread_mutex_lock(&(pool->lock)) != 0) {
        return threadpool_lock_failure;
    }

    next = pool->tail + 1;
    next = (next == pool->queue_size) ? 0 : next;

    do {
        
        if(pool->count == pool->queue_size) {
            err = threadpool_queue_full;
            break;
        }

        
        if(pool->shutdown) {
            err = threadpool_shutdown;
            break;
        }

        pool->queue[pool->tail].function = function;
        pool->queue[pool->tail].argument = argument;
        pool->tail = next;
        pool->count += 1;

       
        if(pthread_cond_signal(&(pool->notify)) != 0) {
            err = threadpool_lock_failure;
            break;
        }
        
    } while(0);

    if(pthread_mutex_unlock(&pool->lock) != 0) {
        err = threadpool_lock_failure;
    }

    return err;
}

int threadpool_destroy(threadpool_t *pool, int flags)
{
    int i, err = 0;

    if(pool == NULL) {
        return threadpool_invalid;
    }

    if(pthread_mutex_lock(&(pool->lock)) != 0) {
        return threadpool_lock_failure;
    }

    do {
        
        if(pool->shutdown) {
            err = threadpool_shutdown;
            break;
        }

        pool->shutdown = (flags & threadpool_graceful) ?
            graceful_shutdown : immediate_shutdown;

        if((pthread_cond_broadcast(&(pool->notify)) != 0) ||
           (pthread_mutex_unlock(&(pool->lock)) != 0)) {
            err = threadpool_lock_failure;
            break;
        }

        for(i = 0; i < pool->thread_count; i++) {
            if(pthread_join(pool->threads[i], NULL) != 0) {
                err = threadpool_thread_failure;
            }
        }
    } while(0);

    if(!err) {
        threadpool_free(pool);
    }
    return err;
}

int threadpool_free(threadpool_t *pool)
{
    if(pool == NULL || pool->started > 0) {
        return -1;
    }

    if(pool->threads) {
        free(pool->threads);
        free(pool->queue);

        pthread_mutex_lock(&(pool->lock));
        pthread_mutex_destroy(&(pool->lock));
        pthread_cond_destroy(&(pool->notify));
    }
    free(pool);
    return 0;
}


static void *threadpool_thread(void *threadpool)
{
    threadpool_t *pool = (threadpool_t *)threadpool;
    threadpool_task_t task;

    for(;;) {
        
        pthread_mutex_lock(&(pool->lock));

        while((pool->count == 0) && (!pool->shutdown)) {
            pthread_cond_wait(&(pool->notify), &(pool->lock));
        }

        if((pool->shutdown == immediate_shutdown) ||
           ((pool->shutdown == graceful_shutdown) &&
            (pool->count == 0))) {
            break;
        }

        task.function = pool->queue[pool->head].function;
        task.argument = pool->queue[pool->head].argument;
        pool->head += 1;
        pool->head = (pool->head == pool->queue_size) ? 0 : pool->head;
        pool->count -= 1;

        pthread_mutex_unlock(&(pool->lock));

        (*(task.function))(task.argument);
    }

    pool->started--;

    pthread_mutex_unlock(&(pool->lock));
    pthread_exit(NULL);
    return(NULL);
}
