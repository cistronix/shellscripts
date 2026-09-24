#define _GNU_SOURCE

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define KMSG_PATH       "/dev/kmsg"
#define LOG_PREFIX      "usermode-helper-logger"
#define KMSG_PRI        "<12>"

#define CONFIG_PATH     "/etc/usermode-helper.conf"
#define DISPATCHER_PATH "/sbin/usermode-helper"

#define MAX_LOG_LEN     3800
#define TRUNC_MARKER    " ...<truncated>"

#define CONFIG_LINE_MAX 4096
#define CONFIG_MAX_SIZE (64 * 1024)
#define MAX_TOKENS      64

extern char **environ;


struct logbuf {
    char   *data;
    size_t  size;
    size_t  len;
    size_t  limit;
    bool    truncated;
};


static void
logbuf_init(struct logbuf *lb, char *data, size_t size)
{
    const size_t reserve = sizeof(TRUNC_MARKER) - 1;

    lb->data      = data;
    lb->size      = size;
    lb->len       = 0;
    lb->truncated = false;

    if (size == 0) {
        lb->limit = 0;
        return;
    }

    data[0] = '\0';

    lb->limit = size > reserve + 1
              ? size - reserve - 1
              : 0;
}


static size_t
logbuf_room(const struct logbuf *lb)
{
    return lb->len < lb->limit
         ? lb->limit - lb->len
         : 0;
}


static bool
logbuf_append_mem(struct logbuf *lb, const char *src, size_t n)
{
    if (lb->truncated)
        return false;

    if (n > logbuf_room(lb)) {
        lb->truncated = true;
        return false;
    }

    memcpy(lb->data + lb->len, src, n);

    lb->len += n;
    lb->data[lb->len] = '\0';

    return true;
}


static bool
__attribute__((format(printf, 2, 3)))
logbuf_appendf(struct logbuf *lb, const char *fmt, ...)
{
    char tmp[256];
    va_list ap;
    int n;

    if (lb->truncated)
        return false;

    va_start(ap, fmt);
    n = vsnprintf(tmp, sizeof(tmp), fmt, ap);
    va_end(ap);

    if (n < 0 || (size_t)n >= sizeof(tmp)) {
        lb->truncated = true;
        return false;
    }

    return logbuf_append_mem(lb, tmp, (size_t)n);
}


static bool
logbuf_append_escaped(struct logbuf *lb, const char *src)
{
    const unsigned char *p;

    if (lb->truncated)
        return false;

    if (src == NULL)
        src = "(null)";

    if (logbuf_room(lb) < 2) {
        lb->truncated = true;
        return false;
    }

    lb->data[lb->len++] = '"';
    lb->data[lb->len] = '\0';

    for (p = (const unsigned char *)src; *p != '\0'; ++p) {
        char esc[4];
        const char *out;
        size_t out_len;

        switch (*p) {
        case '\n':
            out = "\\n";
            out_len = 2;
            break;

        case '\r':
            out = "\\r";
            out_len = 2;
            break;

        case '\t':
            out = "\\t";
            out_len = 2;
            break;

        case '\\':
            out = "\\\\";
            out_len = 2;
            break;

        case '"':
            out = "\\\"";
            out_len = 2;
            break;

        default:
            if (*p < 0x20 || *p == 0x7f) {
                esc[0] = '\\';
                esc[1] = (char)('0' + ((*p >> 6) & 0x07));
                esc[2] = (char)('0' + ((*p >> 3) & 0x07));
                esc[3] = (char)('0' + (*p & 0x07));

                out = esc;
                out_len = sizeof(esc);
            } else {
                esc[0] = (char)*p;

                out = esc;
                out_len = 1;
            }

            break;
        }

        if (logbuf_room(lb) < out_len + 1) {
            lb->truncated = true;
            break;
        }

        memcpy(lb->data + lb->len, out, out_len);

        lb->len += out_len;
        lb->data[lb->len] = '\0';
    }

    if (lb->len < lb->limit) {
        lb->data[lb->len++] = '"';
        lb->data[lb->len] = '\0';
    } else {
        lb->truncated = true;
    }

    return !lb->truncated;
}


static void
logbuf_finish(struct logbuf *lb)
{
    const size_t marker_len = sizeof(TRUNC_MARKER) - 1;

    if (lb->size == 0)
        return;

    if (lb->truncated) {
        size_t room;
        size_t n;

        room = lb->size - 1 - lb->len;
        n = marker_len < room
          ? marker_len
          : room;

        memcpy(lb->data + lb->len, TRUNC_MARKER, n);
        lb->len += n;
    }

    lb->data[lb->len] = '\0';
}


static void
stderr_log_failure(const char *what, int err, const char *msg)
{
    if (err != 0) {
        fprintf(stderr,
                "%s: %s: %s; message: %s\n",
                LOG_PREFIX,
                what,
                strerror(err),
                msg);
    } else {
        fprintf(stderr,
                "%s: %s; message: %s\n",
                LOG_PREFIX,
                what,
                msg);
    }
}


static void
log_to_kmsg(const char *msg)
{
    char line[
        MAX_LOG_LEN
        + sizeof(LOG_PREFIX)
        + sizeof(KMSG_PRI)
        + 4
    ];

    int fd;
    int n;
    ssize_t written;

    fd = open(KMSG_PATH,
              O_WRONLY |
              O_NOCTTY |
              O_CLOEXEC);

    if (fd < 0) {
        int err = errno;

        stderr_log_failure(
            "could not open " KMSG_PATH,
            err,
            msg
        );

        return;
    }

    n = snprintf(line,
                 sizeof(line),
                 KMSG_PRI "%s: %s\n",
                 LOG_PREFIX,
                 msg);

    if (n < 0 || (size_t)n >= sizeof(line)) {
        close(fd);

        stderr_log_failure(
            "internal log-line overflow",
            0,
            msg
        );

        return;
    }

    do {
        written = write(fd, line, (size_t)n);
    } while (written < 0 && errno == EINTR);

    if (written < 0) {
        int err = errno;

        close(fd);

        stderr_log_failure(
            "write to " KMSG_PATH " failed",
            err,
            msg
        );

        return;
    }

    if (written != (ssize_t)n) {
        close(fd);

        stderr_log_failure(
            "short write to " KMSG_PATH,
            0,
            msg
        );

        return;
    }

    close(fd);
}

enum config_result {
    CONFIG_MATCH,
    CONFIG_NO_MATCH,
    CONFIG_ERROR
};

static int
tokenize_line(char *line,
              char *tokens[],
              size_t max_tokens,
              char *err,
              size_t err_size)
{
    char *p = line;
    size_t ntokens = 0;

    for (;;) {
        char *start;
        char *w;
        char quote = '\0';

        while (*p != '\0' &&
               isspace((unsigned char)*p))
            ++p;

        if (*p == '\0' || *p == '#')
            break;

        if (ntokens == max_tokens) {
            snprintf(err,
                     err_size,
                     "too many tokens (max %zu)",
                     max_tokens);

            return -1;
        }

        start = p;
        w = p;

        while (*p != '\0') {
            unsigned char c = (unsigned char)*p;

            if (quote == '\0' &&
                isspace(c))
                break;

            if (quote == '\0' &&
                (c == '\'' || c == '"')) {
                quote = (char)c;
                ++p;
                continue;
            }

            if (quote != '\0' &&
                c == (unsigned char)quote) {
                quote = '\0';
                ++p;
                continue;
            }

            if (c == '\\' && quote != '\'') {
                ++p;

                if (*p == '\0') {
                    snprintf(err,
                             err_size,
                             "trailing backslash");

                    return -1;
                }

                *w++ = *p++;
                continue;
            }

            *w++ = *p++;
        }

        if (quote != '\0') {
            snprintf(err,
                     err_size,
                     "unterminated quote");

            return -1;
        }

        if (*p != '\0')
            ++p;

        *w = '\0';

        tokens[ntokens++] = start;
    }

    return (int)ntokens;
}

static bool
argv_matches_exact(int argc,
                   char *argv[],
                   char *tokens[],
                   int ntokens)
{
    int wanted_argc = ntokens - 1;
    int i;

    if (argc != wanted_argc)
        return false;

    for (i = 0; i < argc; ++i) {
        if (argv[i] == NULL ||
            strcmp(argv[i],
                   tokens[i + 1]) != 0)
            return false;
    }

    return true;
}

static bool
argv_matches_prefix(int argc,
                    char *argv[],
                    char *tokens[],
                    int ntokens)
{
    int prefix_argc = ntokens - 1;
    int i;

    if (argc < prefix_argc)
        return false;

    for (i = 0; i < prefix_argc; ++i) {
        if (argv[i] == NULL ||
            strcmp(argv[i],
                   tokens[i + 1]) != 0)
            return false;
    }

    return true;
}

static enum config_result
evaluate_config(int argc,
                char *argv[],
                unsigned long *matched_line,
                char *err,
                size_t err_size)
{
    int fd;
    struct stat st;
    FILE *fp;

    char line[CONFIG_LINE_MAX];

    unsigned long line_no = 0;
    unsigned long first_match = 0;

    bool matched = false;

    *matched_line = 0;
    err[0] = '\0';

    fd = open(CONFIG_PATH,
              O_RDONLY |
              O_CLOEXEC |
              O_NOFOLLOW);

    if (fd < 0) {
        snprintf(err,
                 err_size,
                 "cannot open %s: %s",
                 CONFIG_PATH,
                 strerror(errno));

        return CONFIG_ERROR;
    }


    if (fstat(fd, &st) < 0) {
        int saved_errno = errno;

        close(fd);

        snprintf(err,
                 err_size,
                 "cannot stat %s: %s",
                 CONFIG_PATH,
                 strerror(saved_errno));

        return CONFIG_ERROR;
    }


    if (!S_ISREG(st.st_mode)) {
        close(fd);

        snprintf(err,
                 err_size,
                 "%s is not a regular file",
                 CONFIG_PATH);

        return CONFIG_ERROR;
    }


    if (st.st_uid != 0) {
        close(fd);

        snprintf(err,
                 err_size,
                 "%s is not owned by root",
                 CONFIG_PATH);

        return CONFIG_ERROR;
    }


    if ((st.st_mode &
         (S_IWGRP | S_IWOTH)) != 0) {

        close(fd);

        snprintf(err,
                 err_size,
                 "%s is group/world writable",
                 CONFIG_PATH);

        return CONFIG_ERROR;
    }


    if (st.st_size < 0 ||
        st.st_size > CONFIG_MAX_SIZE) {

        close(fd);

        snprintf(err,
                 err_size,
                 "%s is too large",
                 CONFIG_PATH);

        return CONFIG_ERROR;
    }


    fp = fdopen(fd, "r");

    if (fp == NULL) {
        int saved_errno = errno;

        close(fd);

        snprintf(err,
                 err_size,
                 "fdopen(%s) failed: %s",
                 CONFIG_PATH,
                 strerror(saved_errno));

        return CONFIG_ERROR;
    }


    while (fgets(line,
                 sizeof(line),
                 fp) != NULL) {

        char *tokens[MAX_TOKENS];
        char parse_err[128];

        size_t len;
        int ntokens;
        bool this_match = false;

        ++line_no;

        len = strlen(line);


        if (len > 0 &&
            line[len - 1] != '\n' &&
            !feof(fp)) {

            snprintf(err,
                     err_size,
                     "%s:%lu: line too long",
                     CONFIG_PATH,
                     line_no);

            fclose(fp);

            return CONFIG_ERROR;
        }


        if (len > 0 &&
            line[len - 1] == '\n')
            line[len - 1] = '\0';


        parse_err[0] = '\0';

        ntokens = tokenize_line(
            line,
            tokens,
            MAX_TOKENS,
            parse_err,
            sizeof(parse_err)
        );


        if (ntokens < 0) {
            snprintf(err,
                     err_size,
                     "%s:%lu: %s",
                     CONFIG_PATH,
                     line_no,
                     parse_err);

            fclose(fp);

            return CONFIG_ERROR;
        }


        if (ntokens == 0)
            continue;


        if (strcmp(tokens[0],
                   "allow-path") == 0) {

            if (ntokens != 2) {
                snprintf(
                    err,
                    err_size,
                    "%s:%lu: "
                    "allow-path requires exactly one path",
                    CONFIG_PATH,
                    line_no
                );

                fclose(fp);

                return CONFIG_ERROR;
            }


            if (tokens[1][0] != '/') {
                snprintf(
                    err,
                    err_size,
                    "%s:%lu: "
                    "helper path must be absolute",
                    CONFIG_PATH,
                    line_no
                );

                fclose(fp);

                return CONFIG_ERROR;
            }


            this_match =
                argc > 0 &&
                argv[0] != NULL &&
                strcmp(argv[0],
                       tokens[1]) == 0;
        }


        else if (strcmp(tokens[0],
                        "allow-exact") == 0) {

            if (ntokens < 2) {
                snprintf(
                    err,
                    err_size,
                    "%s:%lu: "
                    "allow-exact requires a helper path",
                    CONFIG_PATH,
                    line_no
                );

                fclose(fp);

                return CONFIG_ERROR;
            }


            if (tokens[1][0] != '/') {
                snprintf(
                    err,
                    err_size,
                    "%s:%lu: "
                    "helper path must be absolute",
                    CONFIG_PATH,
                    line_no
                );

                fclose(fp);

                return CONFIG_ERROR;
            }


            this_match =
                argv_matches_exact(
                    argc,
                    argv,
                    tokens,
                    ntokens
                );
        }


        else if (strcmp(tokens[0],
                        "allow-prefix") == 0) {

            if (ntokens < 3) {
                snprintf(
                    err,
                    err_size,
                    "%s:%lu: "
                    "allow-prefix requires a helper path "
                    "and at least one argument",
                    CONFIG_PATH,
                    line_no
                );

                fclose(fp);

                return CONFIG_ERROR;
            }


            if (tokens[1][0] != '/') {
                snprintf(
                    err,
                    err_size,
                    "%s:%lu: "
                    "helper path must be absolute",
                    CONFIG_PATH,
                    line_no
                );

                fclose(fp);

                return CONFIG_ERROR;
            }


            this_match =
                argv_matches_prefix(
                    argc,
                    argv,
                    tokens,
                    ntokens
                );
        }

        else {
            snprintf(
                err,
                err_size,
                "%s:%lu: unknown directive '%s'",
                CONFIG_PATH,
                line_no,
                tokens[0]
            );

            fclose(fp);

            return CONFIG_ERROR;
        }

        if (this_match && !matched) {
            matched = true;
            first_match = line_no;
        }
    }


    if (ferror(fp)) {
        int saved_errno = errno;

        fclose(fp);

        snprintf(
            err,
            err_size,
            "error reading %s: %s",
            CONFIG_PATH,
            strerror(saved_errno)
        );

        return CONFIG_ERROR;
    }


    if (fclose(fp) != 0) {
        snprintf(
            err,
            err_size,
            "error closing %s: %s",
            CONFIG_PATH,
            strerror(errno)
        );

        return CONFIG_ERROR;
    }


    if (matched) {
        *matched_line = first_match;
        return CONFIG_MATCH;
    }


    return CONFIG_NO_MATCH;
}


static bool
executable_is_safe(const char *path,
                   char *err,
                   size_t err_size)
{
    struct stat st;
    struct stat self_st;


    if (path == NULL ||
        path[0] != '/') {

        snprintf(
            err,
            err_size,
            "helper path is not absolute"
        );

        return false;
    }

    if (stat(path, &st) < 0) {
        snprintf(
            err,
            err_size,
            "cannot stat helper: %s",
            strerror(errno)
        );

        return false;
    }


    if (!S_ISREG(st.st_mode)) {
        snprintf(
            err,
            err_size,
            "helper target is not a regular file"
        );

        return false;
    }


    if ((st.st_mode &
         (S_IXUSR | S_IXGRP | S_IXOTH)) == 0) {

        snprintf(
            err,
            err_size,
            "helper target has no execute bit set"
        );

        return false;
    }

    if (st.st_uid != 0) {
        snprintf(
            err,
            err_size,
            "helper target is not owned by root"
        );

        return false;
    }


    if ((st.st_mode &
         (S_IWGRP | S_IWOTH)) != 0) {

        snprintf(
            err,
            err_size,
            "helper target is group/world writable"
        );

        return false;
    }

    if (stat(DISPATCHER_PATH,
             &self_st) == 0 &&
        st.st_dev == self_st.st_dev &&
        st.st_ino == self_st.st_ino) {

        snprintf(
            err,
            err_size,
            "helper target resolves to the dispatcher itself"
        );

        return false;
    }


    return true;
}

static void
log_invocation(const char *decision,
               int argc,
               char *argv[],
               unsigned long rule_line,
               const char *reason)
{
    char buf[MAX_LOG_LEN];
    struct logbuf lb;

    const char *helper;
    int i;


    logbuf_init(
        &lb,
        buf,
        sizeof(buf)
    );


    helper =
        argc > 0 &&
        argv != NULL &&
        argv[0] != NULL
        ? argv[0]
        : "(unknown)";


    logbuf_appendf(
        &lb,

        "%s "
        "helper_pid=%ld "
        "helper_ppid=%ld "
        "uid=%lu "
        "euid=%lu "
        "gid=%lu "
        "egid=%lu "
        "argc=%d",

        decision,

        (long)getpid(),
        (long)getppid(),

        (unsigned long)getuid(),
        (unsigned long)geteuid(),

        (unsigned long)getgid(),
        (unsigned long)getegid(),

        argc
    );

    if (rule_line != 0) {
        logbuf_appendf(
            &lb,
            " rule_line=%lu",
            rule_line
        );
    }

    if (reason != NULL) {
        logbuf_append_mem(
            &lb,
            " reason=",
            sizeof(" reason=") - 1
        );

        logbuf_append_escaped(
            &lb,
            reason
        );
    }


    logbuf_append_mem(
        &lb,
        " helper=",
        sizeof(" helper=") - 1
    );

    logbuf_append_escaped(
        &lb,
        helper
    );


    for (i = 1;
         i < argc && !lb.truncated;
         ++i) {

        if (!logbuf_appendf(
                &lb,
                " argv[%d]=",
                i))
            break;

        if (!logbuf_append_escaped(
                &lb,
                argv[i]))
            break;
    }


    logbuf_finish(&lb);

    log_to_kmsg(buf);
}

int
main(int argc, char *argv[])
{
    enum config_result result;

    unsigned long rule_line;

    char err[256];

    result = evaluate_config(
        argc,
        argv,
        &rule_line,
        err,
        sizeof(err)
    );

    if (result == CONFIG_ERROR) {
        log_invocation(
            "DENY",
            argc,
            argv,
            0,
            err
        );

        _exit(1);
    }

    if (result == CONFIG_NO_MATCH) {
        log_invocation(
            "DENY",
            argc,
            argv,
            0,
            "no matching allow rule"
        );

        _exit(1);
    }

  if (argc <= 0 ||
        argv == NULL ||
        argv[0] == NULL) {

        log_invocation(
            "DENY",
            argc,
            argv,
            rule_line,
            "missing helper path"
        );

        _exit(1);
    }

    if (!executable_is_safe(
            argv[0],
            err,
            sizeof(err))) {

        log_invocation(
            "DENY",
            argc,
            argv,
            rule_line,
            err
        );

        _exit(1);
    }

    log_invocation(
        "ALLOW",
        argc,
        argv,
        rule_line,
        NULL
    );

    execve(
        argv[0],
        argv,
        environ
    );

    snprintf(
        err,
        sizeof(err),
        "execve failed: %s",
        strerror(errno)
    );

    log_invocation(
        "EXECFAIL",
        argc,
        argv,
        rule_line,
        err
    );


    _exit(127);
}
