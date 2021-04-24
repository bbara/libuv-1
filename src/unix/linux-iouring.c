#include <errno.h>
#include <sys/sysmacros.h>

#if defined(LIBUV_LIBURING)
#include <liburing.h>
#include <sys/syscall.h>
#include <unistd.h>
#endif

#include "internal.h"
#include "uv.h"

/* The io_uring submission and completion queues have fixed sizes (CQ twice the
 * size of the SQ). This must be a power of two, in the range
 * [1, IORING_MAX_ENTRIES (currently 4096)]. Currently, if more reqs that use
 * io_uring are issued in one loop iteration than the queues can hold, then the
 * overflowing requests are handled by the threadpool impl.
 * Additionally, the number is capped by ulimit -l ('memlock').
 * If the memlock is reached, io_uring_queue_init() throws ENOMEM.
 */
#ifndef IOURING_SQ_SIZE
#define IOURING_SQ_SIZE 32
#endif

#if defined(LIBUV_LIBURING)
/* taken from the internals of liburing */
int __sys_io_uring_enter2(int fd, unsigned to_submit, unsigned min_complete,
                          unsigned flags, sigset_t* sig, int sz) {
  return syscall(__NR_io_uring_enter, fd, to_submit, min_complete, flags, sig,
                 sz);
}

/* taken from the internals of liburing */
int __sys_io_uring_enter(int fd, unsigned to_submit, unsigned min_complete,
                         unsigned flags, sigset_t* sig) {
  return __sys_io_uring_enter2(fd, to_submit, min_complete, flags, sig,
                               _NSIG / 8);
}

/* taken from the internals of liburing */
static int __io_uring_flush_sq(struct io_uring* ring) {
  struct io_uring_sq* sq = &ring->sq;
  const unsigned mask = *sq->kring_mask;
  unsigned ktail, to_submit;

  if (sq->sqe_head == sq->sqe_tail) {
    ktail = *sq->ktail;
    goto out;
  }

  /*
   * Fill in sqes that we have queued up, adding them to the kernel ring
   */
  ktail = *sq->ktail;
  to_submit = sq->sqe_tail - sq->sqe_head;
  while (to_submit--) {
    sq->array[ktail & mask] = sq->sqe_head & mask;
    ktail++;
    sq->sqe_head++;
  }

  /*
   * Ensure that the kernel sees the SQE updates before it sees the tail
   * update.
   */
  io_uring_smp_store_release(sq->ktail, ktail);
out:
  /*
   * This _may_ look problematic, as we're not supposed to be reading
   * SQ->head without acquire semantics. When we're in SQPOLL mode, the
   * kernel submitter could be updating this right now. For non-SQPOLL,
   * task itself does it, and there's no potential race. But even for
   * SQPOLL, the load is going to be potentially out-of-date the very
   * instant it's done, regardless or whether or not it's done
   * atomically. Worst case, we're going to be over-estimating what
   * we can submit. The point is, we need to be able to deal with this
   * situation regardless of any perceived atomicity.
   */
  return ktail - *sq->khead;
}

/* taken from the internals of liburing */
static int __io_uring_submit(struct io_uring* ring, unsigned submitted,
                             unsigned wait_nr) {
  unsigned flags;
  int ret;

  flags = 0;
  if (true || wait_nr) {
    if (wait_nr || (ring->flags & IORING_SETUP_IOPOLL))
      flags |= IORING_ENTER_GETEVENTS;

    ret = __sys_io_uring_enter(ring->ring_fd, submitted, wait_nr, flags, NULL);
    if (ret < 0) return -errno;
  } else
    ret = submitted;

  return ret;
}

struct uv__backend_data_io_uring {
  int fd;
  int32_t pending;
  struct io_uring ring;
  uv_poll_t poll_handle;
};

static int uv__io_uring_fs_get_sqe(uv_loop_t* loop, uv_fs_t* req,
                                   struct io_uring_sqe** sqe_buf) {
  struct uv__backend_data_io_uring* backend_data;

  if (loop == NULL || req == NULL || sqe_buf == NULL) {
    return UV_EINVAL;
  }

  if (!(loop->flags & UV_LOOP_USE_IOURING)) return UV_ENOSYS;

  /* Explicit request to use the threadpool instead. */
  if (req->priv.fs_req_engine == UV__ENGINE_THREADPOOL) return UV_ENOTSUP;

  backend_data = loop->backend.data;

  /* The CQ is 2x the size of the SQ, but the kernel quickly frees up the slot
   * in the SQ after submission, so we could potentially overflow it if we
   * submit a ton of SQEs in one loop iteration.
   */
  if (!io_uring_sq_space_left(&backend_data->ring)) return UV_ENOMEM;

  *sqe_buf = io_uring_get_sqe(&backend_data->ring);
  /* See TODO where #define IOURING_SQ_SIZE is. */
  if (*sqe_buf == NULL) return UV_ENOMEM;

  return 0;
}

static int uv__io_uring_fs_submit(uv_loop_t* loop, uv_fs_t* req,
                                  struct io_uring_sqe* sqe) {
  if (loop == NULL || req == NULL) return UV_EINVAL;

  req->priv.fs_req_engine |= UV__ENGINE_IOURING;

  /* leave the user data NULL to signal a cancel request */
  if (sqe->opcode != IORING_OP_ASYNC_CANCEL)
    sqe->user_data = (uint64_t)req;

  /* leave submitting to the run method of the loop */
  return 0;
}

static int uv__platform_fs_statx_done(uv_loop_t* loop, uv_fs_t* req) {
  struct uv__statx* statxbuf;
  uv_stat_t* buf;

  statxbuf = (struct uv__statx*)req->iouring_buf;
  buf = &req->statbuf;

  buf->st_dev = makedev(statxbuf->stx_dev_major, statxbuf->stx_dev_minor);
  buf->st_mode = statxbuf->stx_mode;
  buf->st_nlink = statxbuf->stx_nlink;
  buf->st_uid = statxbuf->stx_uid;
  buf->st_gid = statxbuf->stx_gid;
  buf->st_rdev = makedev(statxbuf->stx_rdev_major, statxbuf->stx_rdev_minor);
  buf->st_ino = statxbuf->stx_ino;
  buf->st_size = statxbuf->stx_size;
  buf->st_blksize = statxbuf->stx_blksize;
  buf->st_blocks = statxbuf->stx_blocks;
  buf->st_atim.tv_sec = statxbuf->stx_atime.tv_sec;
  buf->st_atim.tv_nsec = statxbuf->stx_atime.tv_nsec;
  buf->st_mtim.tv_sec = statxbuf->stx_mtime.tv_sec;
  buf->st_mtim.tv_nsec = statxbuf->stx_mtime.tv_nsec;
  buf->st_ctim.tv_sec = statxbuf->stx_ctime.tv_sec;
  buf->st_ctim.tv_nsec = statxbuf->stx_ctime.tv_nsec;
  buf->st_birthtim.tv_sec = statxbuf->stx_btime.tv_sec;
  buf->st_birthtim.tv_nsec = statxbuf->stx_btime.tv_nsec;
  buf->st_flags = 0;
  buf->st_gen = 0;

  uv__free(statxbuf);
  return 0;
}

/* Return values:
 * 0 on success.
 * UV_ENOSYS if io_uring is not available.
 * UV_ENOTSUP if the request is not async.
 * UV_ENOTSUP if off == -1.
 * UV_ENOTSUP if req->fs_req_engine == UV__ENGINE_THREADPOOL, which means the
 * operation is explicitly required to use the threadpool.
 * UV_ENOMEM if the SQ is full or the CQ might become full.
 * UV_UNKNOWN if no jobs were successfully submitted. (Should not happen.)
 * Any of the errors that may be set by io_uring_enter(2).
 */
static int uv__io_uring_fs_work(uint8_t opcode, uv_loop_t* loop, uv_fs_t* req,
                                uv_os_fd_t file, const uv_buf_t bufs[],
                                unsigned int nbufs, int64_t off, uv_fs_cb cb) {
  struct io_uring_sqe* sqe;
  int rc;

  if (cb == NULL || loop == NULL) return UV_ENOTSUP;

  /* io_uring does not support current-position ops, and we can't achieve atomic
   * behavior with lseek(2). TODO it can in Linux 5.4+
   */
  if (off < 0) return UV_ENOTSUP;

  if ((rc = uv__io_uring_fs_get_sqe(loop, req, &sqe) != 0)) return rc;

  sqe->opcode = opcode;
  sqe->fd = file;
  sqe->off = off;
  sqe->addr = (uint64_t)req->bufs;
  sqe->len = nbufs;

  return uv__io_uring_fs_submit(loop, req, sqe);
}

int uv__io_uring_fd_get(const uv_loop_t* loop) {
  return ((struct uv__backend_data_io_uring*)loop->backend.data)->fd;
}

void uv__io_uring_fd_set(uv_loop_t* loop, int fd) {
  ((struct uv__backend_data_io_uring*)loop->backend.data)->fd = fd;
}

int uv__io_uring_init(uv_loop_t* loop, int fd) {
  struct uv__backend_data_io_uring* backend_data;
  struct io_uring* ring;
  int rc;

  backend_data = uv__malloc(sizeof(*backend_data));
  if (backend_data == NULL) return UV_ENOMEM;
  backend_data->pending = 0;

  ring = &backend_data->ring;

  rc = io_uring_queue_init(IOURING_SQ_SIZE, ring, 0);

  if (rc != 0) {
    uv__free(backend_data);
    backend_data = NULL;
    return UV__ERR(rc);
  }

  rc = uv__cloexec(fd, 1);
  if (rc) {
    io_uring_queue_exit(ring);
    uv__free(backend_data);
    backend_data = NULL;
    return UV__ERR(rc);
  }

  backend_data->fd = fd;

  uv__handle_init(loop, &backend_data->poll_handle, UV_POLL);
  backend_data->poll_handle.flags |= UV_HANDLE_INTERNAL;
  uv__io_init(&backend_data->poll_handle.io_watcher, uv__io_uring_done,
              ring->ring_fd);

  loop->flags |= UV_LOOP_USE_IOURING;
  loop->backend.data = backend_data;
  return 0;
}

void uv__io_uring_done(uv_loop_t* loop, uv__io_t* w, unsigned int events) {
  uv_poll_t* handle;
  struct io_uring* ring;
  struct uv__backend_data_io_uring* backend_data;
  struct io_uring_cqe* cqe;
  uv_fs_t* req;
  int finished1;

  handle = container_of(w, uv_poll_t, io_watcher);
  backend_data = loop->backend.data;
  ring = &backend_data->ring;

  finished1 = 0;
  while (1) { /* Drain the CQ. */
    io_uring_peek_cqe(ring, &cqe);

    if (cqe == NULL) break;

    assert(backend_data->pending > 0);
    if (--backend_data->pending == 0) uv_poll_stop(handle);

    io_uring_cq_advance(ring, 1);

    req = (void*)(uintptr_t)cqe->user_data;
    if (req == NULL) {
      /* this is a cancel submission, we ignore it */
      continue;
    }

    /* uv_cancel sets result to UV_ECANCELED. Don't overwrite that. */
    if (req->result == 0) req->result = cqe->res;

    if (req->result == -EINVAL) {
      /* io_uring doesn't support some operations that read/write do (e.g. readv
       * on stdin). Retry with the threadpool impl.
       */
      req->result = 0;
      req->priv.fs_req_engine = UV__ENGINE_THREADPOOL;

      switch (req->fs_type) {
        case UV_FS_WRITE:
        case UV_FS_READ:
        case UV_FS_FSYNC:
          uv__req_register(loop, req);
          uv__work_submit(loop, &req->work_req, UV__WORK_FAST_IO, uv__fs_work,
                          uv__fs_done);
          break;
        default:
          UNREACHABLE();
      }
    } else {
      switch (req->fs_type) {
        case UV_FS_FSTAT:
          req->path = NULL;
          /* FALLTHROUGH */
        case UV_FS_STAT:
        case UV_FS_LSTAT:
          uv__platform_fs_statx_done(loop, req);
          req->ptr = &req->statbuf;
          break;
        default:
          break;
      }

      req->cb(req);
    }

    finished1 = 1;
  }

  assert(finished1 && "io_uring signal raised but no CQEs retrieved");
}

int uv__io_uring_submit(uv_loop_t* loop) {
  int submitted;
  uv_poll_t* handle;
  struct uv__backend_data_io_uring* backend_data;

  if (loop == NULL) return UV_EINVAL;

  backend_data = loop->backend.data;

  /* submit work one by one, otherwise canceled jobs won't get submitted at all.
   * In this case, the liburing_done won't be called and therefore the CBs never
   * called too. */
  while (__io_uring_flush_sq(&backend_data->ring)) {
    submitted = __io_uring_submit(&backend_data->ring, 1, 0);
    if (submitted < 0) {
      return UV__ERR(errno);
    }
    assert(submitted == 1 && "submitted job amount != 1");
    if (backend_data->pending == 0) {
      handle = &backend_data->poll_handle;
      uv__io_start(loop, &handle->io_watcher, POLLIN);
      uv__handle_start(handle);
    }
    backend_data->pending += submitted;
  }
  return 0;
}

void uv__io_uring_delete(uv_loop_t* loop) {
  struct uv__backend_data_io_uring* backend_data;
  int backend_fd;

  if (loop->flags & UV_LOOP_USE_IOURING) {
    /* Free data and switch back to fd (other cleanup code needs the fd). */
    backend_data = loop->backend.data;
    backend_fd = backend_data->fd;
    io_uring_queue_exit(&backend_data->ring);
    uv__free(backend_data);
    loop->flags ^= UV_LOOP_USE_IOURING;
    loop->backend.fd = backend_fd;
  }
}

int uv__platform_fs_read(uv_loop_t* loop, uv_fs_t* req, uv_os_fd_t file,
                         const uv_buf_t bufs[], unsigned int nbufs, int64_t off,
                         uv_fs_cb cb) {
  return uv__io_uring_fs_work(IORING_OP_READV, loop, req, file, bufs, nbufs,
                              off, cb);
}

int uv__platform_fs_write(uv_loop_t* loop, uv_fs_t* req, uv_os_fd_t file,
                          const uv_buf_t bufs[], unsigned int nbufs,
                          int64_t off, uv_fs_cb cb) {
  return uv__io_uring_fs_work(IORING_OP_WRITEV, loop, req, file, bufs, nbufs,
                              off, cb);
}

int uv__platform_fs_close(uv_loop_t* loop, uv_fs_t* req, uv_os_fd_t file,
                          uv_fs_cb cb) {
  return uv__io_uring_fs_work(IORING_OP_CLOSE, loop, req, file, NULL, 0, 0, cb);
}

int uv__platform_fs_fsync(uv_loop_t* loop, uv_fs_t* req, uv_os_fd_t file,
                          uv_fs_cb cb) {
  return uv__io_uring_fs_work(IORING_OP_FSYNC, loop, req, file, NULL, 0, 0, cb);
}

int uv__platform_fs_statx(uv_loop_t* loop, uv_fs_t* req, int is_fstat,
                          int is_lstat, uv_fs_cb cb) {
  struct statx* statxbuf;
  struct io_uring_sqe* sqe;
  int dirfd;
  int flags;
  int rc;
  int fd = req->file;
  const char* path = req->path;

  if (cb == NULL || loop == NULL) return UV_ENOTSUP;

  if ((rc = uv__io_uring_fs_get_sqe(loop, req, &sqe)) != 0) return rc;

  statxbuf = uv__malloc(sizeof(*statxbuf));
  if (statxbuf == NULL) {
    return UV_ENOMEM;
  }
  req->iouring_buf = statxbuf;

  dirfd = AT_FDCWD;
  flags = 0; /* AT_STATX_SYNC_AS_STAT */

  if (is_fstat) {
    dirfd = fd;
    flags |= 0x1000; /* AT_EMPTY_PATH */
  }

  if (is_lstat) flags |= AT_SYMLINK_NOFOLLOW;

  io_uring_prep_statx(sqe, dirfd, is_fstat ? "" : path, flags, STATX_ALL,
                      statxbuf);
  return uv__io_uring_fs_submit(loop, req, sqe);
}

int uv__platform_work_cancel(uv_req_t* req) {
  uv_loop_t* loop;
  struct io_uring_sqe* sqe;

  /* TODO io_uring can cancel in some scenarios now. */
  if (req->type == UV_FS &&
      ((uv_fs_t*)req)->priv.fs_req_engine == UV__ENGINE_IOURING) {
    loop = ((uv_fs_t*)req)->loop;
    ((uv_fs_t*)req)->result = UV_ECANCELED;

    /* fire and forget the actual uring cancel request */
    if (uv__io_uring_fs_get_sqe(loop, (uv_fs_t*)req, &sqe) != 0) return 0;
    io_uring_prep_cancel(sqe, req, 0);
    uv__io_uring_fs_submit(loop, (uv_fs_t*)req, sqe);
    return 0;
  }

  return UV_ENOSYS;
}

int uv__has_uring_pending(const uv_loop_t* loop) {
  struct uv__backend_data_io_uring* backend_data = loop->backend.data;
  return io_uring_sq_ready(&backend_data->ring) || backend_data->pending;
}
#else
int uv__io_uring_fd_get(const uv_loop_t* loop) { return -1; }

void uv__io_uring_fd_set(uv_loop_t* loop, int fd) {}

int uv__io_uring_init(uv_loop_t* loop, int fd) { return UV_ENOSYS; }

void uv__io_uring_done(uv_loop_t* loop, uv__io_t* w, unsigned int events) {}

int uv__io_uring_submit(uv_loop_t* loop) { return UV_ENOSYS; }

void uv__io_uring_delete(uv_loop_t* loop) {}

int uv__platform_fs_read(uv_loop_t* loop, uv_fs_t* req, uv_os_fd_t file,
                         const uv_buf_t bufs[], unsigned int nbufs, int64_t off,
                         uv_fs_cb cb) {
  return UV_ENOSYS;
}

int uv__platform_fs_write(uv_loop_t* loop, uv_fs_t* req, uv_os_fd_t file,
                          const uv_buf_t bufs[], unsigned int nbufs,
                          int64_t off, uv_fs_cb cb) {
  return UV_ENOSYS;
}

int uv__platform_fs_close(uv_loop_t* loop, uv_fs_t* req, uv_os_fd_t file,
                          uv_fs_cb cb) {
  return UV_ENOSYS;
}

int uv__platform_fs_fsync(uv_loop_t* loop, uv_fs_t* req, uv_os_fd_t file,
                          uv_fs_cb cb) {
  return UV_ENOSYS;
}

int uv__platform_fs_statx(uv_loop_t* loop, uv_fs_t* req, int is_fstat,
                          int is_lstat, uv_fs_cb cb) {
  return UV_ENOSYS;
}

int uv__platform_work_cancel(uv_req_t* req) { return UV_ENOSYS; }
#endif
