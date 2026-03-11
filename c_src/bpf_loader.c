/*
 * bpf_loader.c — Erlang port for loading BPF programs via libbpf.
 *
 * Protocol: {:packet, 2} framing (2-byte big-endian length prefix).
 * Data integers are little-endian.
 *
 * Commands:
 *   LOAD_XDP            (0x01): [0x01][elf_size:4LE][elf:N][iface_len:1][iface:N]
 *   DETACH              (0x02): [0x02][handle:4LE]
 *   MAP_LOOKUP          (0x03): [0x03][handle:4LE][name_len:1][name:N][key_len:4LE][key:N]
 *   MAP_UPDATE          (0x04): [0x04][handle:4LE][name_len:1][name:N][key_len:4LE][key:N][val_len:4LE][val:N][flags:4LE]
 *   MAP_DELETE          (0x05): [0x05][handle:4LE][name_len:1][name:N][key_len:4LE][key:N]
 *   SUBSCRIBE_RINGBUF   (0x06): [0x06][handle:4LE][name_len:1][name:N]
 *   UNSUBSCRIBE_RINGBUF (0x07): [0x07][handle:4LE][name_len:1][name:N]
 *   MAP_GET_NEXT_KEY    (0x08): [0x08][handle:4LE][name_len:1][name:N][key_len:4LE][key:N]
 *                               key_len=0 means "get first key"
 *   LOAD                (0x09): [0x09][elf_size:4LE][elf:N][prog_type:1][target_len:1][target:N]
 *   SUBSCRIBE_PERFBUF   (0x0A): [0x0A][handle:4LE][name_len:1][name:N]
 *   UNSUBSCRIBE_PERFBUF (0x0B): [0x0B][handle:4LE][name_len:1][name:N]
 *
 * Responses:
 *   OK (load):              [0x00][handle:4LE][num_maps:1]([name_len:1][name:N])*
 *   OK (detach/update/sub): [0x00]
 *   OK (lookup found):      [0x00][val_len:4LE][value:N]
 *   NOT_FOUND (lookup/del): [0x02]
 *   ERROR:                  [0x01][message...]
 *
 * Unsolicited events:
 *   RINGBUF_EVENT (0x10): [0x10][handle:4LE][name_len:1][name:N][data_len:4LE][data:N]
 *   PERFBUF_EVENT (0x11): [0x11][handle:4LE][name_len:1][name:N][data_len:4LE][data:N]
 *   PERFBUF_LOST  (0x12): [0x12][handle:4LE][name_len:1][name:N][lost_count:8LE]
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <linux/if_ether.h>
#include <linux/perf_event.h>
#include <linux/pkt_cls.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#define CMD_LOAD_XDP          0x01
#define CMD_DETACH            0x02
#define CMD_MAP_LOOKUP        0x03
#define CMD_MAP_UPDATE        0x04
#define CMD_MAP_DELETE        0x05
#define CMD_SUBSCRIBE_RINGBUF   0x06
#define CMD_UNSUBSCRIBE_RINGBUF 0x07
#define CMD_MAP_GET_NEXT_KEY    0x08
#define CMD_LOAD              0x09
#define CMD_SUBSCRIBE_PERFBUF   0x0A
#define CMD_UNSUBSCRIBE_PERFBUF 0x0B

#define RESP_OK        0x00
#define RESP_ERROR     0x01
#define RESP_NOT_FOUND 0x02
#define RESP_RINGBUF_EVENT 0x10
#define RESP_PERFBUF_EVENT 0x11
#define RESP_PERFBUF_LOST  0x12

#define MAX_OBJECTS  16
#define MAX_RESP     4096
#define MAX_IFACE    64
#define MAX_RINGBUFS 8
#define MAX_PERFBUFS 8
#define MAX_TARGET   256

/* Program type enum — must match Elixir Protocol.prog_type_byte/1 */
#define PROG_TYPE_AUTO          0
#define PROG_TYPE_XDP           1
#define PROG_TYPE_KPROBE        2
#define PROG_TYPE_KRETPROBE     3
#define PROG_TYPE_TRACEPOINT    4
#define PROG_TYPE_RAW_TP        5
#define PROG_TYPE_TC            6
#define PROG_TYPE_SOCKET_FILTER 7
#define PROG_TYPE_CGROUP_SKB    8
#define PROG_TYPE_UPROBE        9
#define PROG_TYPE_URETPROBE     10
#define PROG_TYPE_PERF_EVENT       11
#define PROG_TYPE_LSM              12
#define PROG_TYPE_SK_MSG           13
#define PROG_TYPE_SK_SKB           14
#define PROG_TYPE_CGROUP_SOCK      15
#define PROG_TYPE_CGROUP_SOCK_ADDR 16
#define PROG_TYPE_FLOW_DISSECTOR   17
#define PROG_TYPE_STRUCT_OPS       18

struct loaded_obj {
    struct bpf_object *obj;
    struct bpf_link *link;    /* generic: kprobe, tracepoint, etc. */
    unsigned int ifindex;     /* XDP/TC only */
    uint32_t xdp_flags;      /* XDP only */
    uint8_t prog_type;        /* which type was loaded */
    int cgroup_fd;            /* cgroup_skb/cgroup_sock/cgroup_sock_addr */
    int socket_fd;            /* socket_filter */
    int pe_fd;                /* perf_event fd */
    struct bpf_tc_hook *tc_hook;  /* TC only */
};

struct rb_sub {
    struct ring_buffer *rb;
    uint32_t handle;
    char map_name[64];
    int epoll_fd_val;   /* cached fd for epoll removal */
};

struct pb_sub {
    struct perf_buffer *pb;
    uint32_t handle;
    char map_name[64];
    int epoll_fd_val;   /* cached fd for epoll removal */
};

static struct loaded_obj loaded[MAX_OBJECTS];
static struct rb_sub ringbufs[MAX_RINGBUFS];
static int num_ringbufs = 0;
static struct pb_sub perfbufs[MAX_PERFBUFS];
static int num_perfbufs = 0;
static int epoll_fd = -1;

/* Sentinel pointer to distinguish stdin from ring buffer in epoll dispatch */
#define EPOLL_STDIN_PTR ((void *)(intptr_t)-1)

/* --- I/O helpers for {:packet, 2} framing --- */

static int read_exact(int fd, void *buf, size_t len) {
    size_t got = 0;
    while (got < len) {
        ssize_t n = read(fd, (char *)buf + got, len - got);
        if (n <= 0) return -1;
        got += n;
    }
    return 0;
}

static int write_exact(int fd, const void *buf, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = write(fd, (const char *)buf + sent, len - sent);
        if (n <= 0) return -1;
        sent += n;
    }
    return 0;
}

static int read_frame(uint8_t **out, uint16_t *out_len) {
    uint8_t hdr[2];
    if (read_exact(STDIN_FILENO, hdr, 2) < 0) return -1;
    uint16_t len = ((uint16_t)hdr[0] << 8) | hdr[1];
    if (len == 0) return -1;
    uint8_t *buf = malloc(len);
    if (!buf) return -1;
    if (read_exact(STDIN_FILENO, buf, len) < 0) { free(buf); return -1; }
    *out = buf;
    *out_len = len;
    return 0;
}

static int write_frame(const uint8_t *data, uint16_t len) {
    uint8_t hdr[2] = { (uint8_t)(len >> 8), (uint8_t)(len & 0xFF) };
    if (write_exact(STDOUT_FILENO, hdr, 2) < 0) return -1;
    if (write_exact(STDOUT_FILENO, data, len) < 0) return -1;
    return 0;
}

/* --- Response helpers --- */

static void send_error(const char *msg) {
    size_t mlen = strlen(msg);
    if (mlen > UINT16_MAX - 1) mlen = UINT16_MAX - 1;
    uint16_t flen = 1 + (uint16_t)mlen;
    uint8_t *buf = malloc(flen);
    if (!buf) return;
    buf[0] = RESP_ERROR;
    memcpy(buf + 1, msg, mlen);
    write_frame(buf, flen);
    free(buf);
}

static uint32_t read_le32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void write_le32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v);
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

/* --- Find a free slot --- */

static int alloc_slot(void) {
    for (int i = 0; i < MAX_OBJECTS; i++) {
        if (!loaded[i].obj) return i;
    }
    return -1;
}

/* --- Command handlers --- */

static void handle_load_xdp(const uint8_t *data, uint16_t len) {
    /* Parse: [elf_size:4LE][elf:N][iface_len:1][iface:N] */
    if (len < 5) { send_error("load_xdp: frame too short"); return; }

    uint32_t elf_size = read_le32(data);
    if (elf_size > (uint32_t)(len - 5)) { send_error("load_xdp: bad elf_size"); return; }

    const uint8_t *elf_data = data + 4;
    size_t iface_offset = 4 + (size_t)elf_size;
    uint8_t iface_len = data[iface_offset];
    if (iface_len > (uint16_t)(len - iface_offset - 1)) { send_error("load_xdp: bad iface_len"); return; }

    char iface[MAX_IFACE + 1];
    if (iface_len > MAX_IFACE) { send_error("load_xdp: interface name too long"); return; }
    memcpy(iface, data + iface_offset + 1, iface_len);
    iface[iface_len] = '\0';

    /* Allocate a slot */
    int slot = alloc_slot();
    if (slot < 0) { send_error("load_xdp: no free slots"); return; }

    /* Write ELF to temp file (libbpf needs a path) */
    char tmppath[] = "/tmp/vaisto_bpf_XXXXXX";
    int tmpfd = mkstemp(tmppath);
    if (tmpfd < 0) { send_error("load_xdp: mkstemp failed"); return; }

    if (write_exact(tmpfd, elf_data, elf_size) < 0) {
        close(tmpfd); unlink(tmppath);
        send_error("load_xdp: write temp file failed");
        return;
    }
    close(tmpfd);

    /* Open + load BPF object */
    struct bpf_object *obj = bpf_object__open(tmppath);
    unlink(tmppath);  /* clean up temp file immediately */

    if (!obj) {
        send_error("load_xdp: bpf_object__open failed");
        return;
    }

    if (bpf_object__load(obj) != 0) {
        bpf_object__close(obj);
        send_error("load_xdp: bpf_object__load failed");
        return;
    }

    /* Get first program */
    struct bpf_program *prog = bpf_object__next_program(obj, NULL);
    if (!prog) {
        bpf_object__close(obj);
        send_error("load_xdp: no program found in ELF");
        return;
    }

    int prog_fd = bpf_program__fd(prog);
    if (prog_fd < 0) {
        bpf_object__close(obj);
        send_error("load_xdp: invalid program fd");
        return;
    }

    /* Resolve interface */
    unsigned int ifindex = if_nametoindex(iface);
    if (ifindex == 0) {
        bpf_object__close(obj);
        char errbuf[128];
        snprintf(errbuf, sizeof(errbuf), "load_xdp: unknown interface '%s'", iface);
        send_error(errbuf);
        return;
    }

    /* Attach XDP */
    uint32_t xdp_flags = XDP_FLAGS_SKB_MODE;
    if (bpf_xdp_attach(ifindex, prog_fd, xdp_flags, NULL) != 0) {
        bpf_object__close(obj);
        send_error("load_xdp: bpf_xdp_attach failed");
        return;
    }

    /* Store in slot */
    loaded[slot].obj = obj;
    loaded[slot].link = NULL;
    loaded[slot].ifindex = ifindex;
    loaded[slot].xdp_flags = xdp_flags;
    loaded[slot].prog_type = PROG_TYPE_XDP;

    /* Collect map names */
    struct bpf_map *map;
    uint8_t map_names[MAX_RESP];
    uint16_t map_pos = 0;
    uint8_t num_maps = 0;

    bpf_object__for_each_map(map, obj) {
        const char *name = bpf_map__name(map);
        if (!name) continue;
        uint8_t nlen = (uint8_t)strlen(name);
        if (map_pos + 1 + nlen > (uint16_t)sizeof(map_names)) break;
        map_names[map_pos++] = nlen;
        memcpy(map_names + map_pos, name, nlen);
        map_pos += nlen;
        num_maps++;
    }

    /* Build response: [0x00][handle:4LE][num_maps:1][map_names...] */
    uint16_t resp_len = 1 + 4 + 1 + map_pos;
    uint8_t *resp = malloc(resp_len);
    if (!resp) { send_error("load_xdp: alloc response failed"); return; }
    resp[0] = RESP_OK;
    write_le32(resp + 1, (uint32_t)slot);
    resp[5] = num_maps;
    if (map_pos > 0) memcpy(resp + 6, map_names, map_pos);

    write_frame(resp, resp_len);
    free(resp);
}

/* Helper: collect map names and send load-OK response */
static void send_load_ok(int slot, struct bpf_object *obj) {
    struct bpf_map *map;
    uint8_t map_names[MAX_RESP];
    uint16_t map_pos = 0;
    uint8_t num_maps = 0;

    bpf_object__for_each_map(map, obj) {
        const char *name = bpf_map__name(map);
        if (!name) continue;
        uint8_t nlen = (uint8_t)strlen(name);
        if (map_pos + 1 + nlen > (uint16_t)sizeof(map_names)) break;
        map_names[map_pos++] = nlen;
        memcpy(map_names + map_pos, name, nlen);
        map_pos += nlen;
        num_maps++;
    }

    uint16_t resp_len = 1 + 4 + 1 + map_pos;
    uint8_t *resp = malloc(resp_len);
    if (!resp) { send_error("load: alloc response failed"); return; }
    resp[0] = RESP_OK;
    write_le32(resp + 1, (uint32_t)slot);
    resp[5] = num_maps;
    if (map_pos > 0) memcpy(resp + 6, map_names, map_pos);

    write_frame(resp, resp_len);
    free(resp);
}

/* Helper: open ELF from data, load into kernel, return obj + prog.
 * Caller must close obj on error paths after this returns non-NULL. */
static struct bpf_object *open_and_load_elf(const uint8_t *elf_data, uint32_t elf_size,
                                             struct bpf_program **prog_out,
                                             const char *cmd_name) {
    char tmppath[] = "/tmp/vaisto_bpf_XXXXXX";
    int tmpfd = mkstemp(tmppath);
    if (tmpfd < 0) {
        char errbuf[128];
        snprintf(errbuf, sizeof(errbuf), "%s: mkstemp failed", cmd_name);
        send_error(errbuf);
        return NULL;
    }

    if (write_exact(tmpfd, elf_data, elf_size) < 0) {
        close(tmpfd); unlink(tmppath);
        char errbuf[128];
        snprintf(errbuf, sizeof(errbuf), "%s: write temp file failed", cmd_name);
        send_error(errbuf);
        return NULL;
    }
    close(tmpfd);

    struct bpf_object *obj = bpf_object__open(tmppath);
    unlink(tmppath);

    if (!obj) {
        char errbuf[128];
        snprintf(errbuf, sizeof(errbuf), "%s: bpf_object__open failed", cmd_name);
        send_error(errbuf);
        return NULL;
    }

    if (bpf_object__load(obj) != 0) {
        bpf_object__close(obj);
        char errbuf[128];
        snprintf(errbuf, sizeof(errbuf), "%s: bpf_object__load failed", cmd_name);
        send_error(errbuf);
        return NULL;
    }

    struct bpf_program *prog = bpf_object__next_program(obj, NULL);
    if (!prog) {
        bpf_object__close(obj);
        char errbuf[128];
        snprintf(errbuf, sizeof(errbuf), "%s: no program found in ELF", cmd_name);
        send_error(errbuf);
        return NULL;
    }

    *prog_out = prog;
    return obj;
}

static void handle_load(const uint8_t *data, uint16_t len) {
    /* Parse: [elf_size:4LE][elf:N][prog_type:1][target_len:1][target:N] */
    if (len < 6) { send_error("load: frame too short"); return; }

    uint32_t elf_size = read_le32(data);
    if (elf_size > (uint32_t)(len - 6)) { send_error("load: bad elf_size"); return; }

    const uint8_t *elf_data = data + 4;
    size_t after_elf = 4 + (size_t)elf_size;

    uint8_t prog_type = data[after_elf];
    uint8_t target_len = data[after_elf + 1];
    if (target_len > (uint16_t)(len - after_elf - 2)) { send_error("load: bad target_len"); return; }

    char target[MAX_TARGET + 1];
    if (target_len > MAX_TARGET) { send_error("load: target too long"); return; }
    memcpy(target, data + after_elf + 2, target_len);
    target[target_len] = '\0';

    /* Allocate a slot */
    int slot = alloc_slot();
    if (slot < 0) { send_error("load: no free slots"); return; }

    /* Open + load */
    struct bpf_program *prog;
    struct bpf_object *obj = open_and_load_elf(elf_data, elf_size, &prog, "load");
    if (!obj) return;

    /* Initialize slot */
    loaded[slot].obj = obj;
    loaded[slot].link = NULL;
    loaded[slot].ifindex = 0;
    loaded[slot].xdp_flags = 0;
    loaded[slot].prog_type = prog_type;
    loaded[slot].cgroup_fd = -1;
    loaded[slot].socket_fd = -1;
    loaded[slot].pe_fd = -1;
    loaded[slot].tc_hook = NULL;

    /* Attach based on program type */
    switch (prog_type) {
    case PROG_TYPE_AUTO:
    case PROG_TYPE_XDP: {
        int prog_fd = bpf_program__fd(prog);
        if (prog_fd < 0) {
            bpf_object__close(obj);
            loaded[slot].obj = NULL;
            send_error("load: invalid program fd");
            return;
        }
        unsigned int ifindex = if_nametoindex(target);
        if (ifindex == 0) {
            bpf_object__close(obj);
            loaded[slot].obj = NULL;
            char errbuf[128];
            snprintf(errbuf, sizeof(errbuf), "load: unknown interface '%s'", target);
            send_error(errbuf);
            return;
        }
        uint32_t xdp_flags = XDP_FLAGS_SKB_MODE;
        if (bpf_xdp_attach(ifindex, prog_fd, xdp_flags, NULL) != 0) {
            bpf_object__close(obj);
            loaded[slot].obj = NULL;
            send_error("load: bpf_xdp_attach failed");
            return;
        }
        loaded[slot].ifindex = ifindex;
        loaded[slot].xdp_flags = xdp_flags;
        break;
    }
    case PROG_TYPE_KPROBE:
    case PROG_TYPE_KRETPROBE: {
        int is_retprobe = (prog_type == PROG_TYPE_KRETPROBE);
        struct bpf_link *link = bpf_program__attach_kprobe(prog, is_retprobe, target);
        if (!link) {
            bpf_object__close(obj);
            loaded[slot].obj = NULL;
            char errbuf[128];
            snprintf(errbuf, sizeof(errbuf), "load: attach_kprobe '%s' failed: %s",
                     target, strerror(errno));
            send_error(errbuf);
            return;
        }
        loaded[slot].link = link;
        break;
    }
    case PROG_TYPE_TRACEPOINT: {
        /* target format: "category/event" */
        char *slash = strchr(target, '/');
        if (!slash) {
            bpf_object__close(obj);
            loaded[slot].obj = NULL;
            send_error("load: tracepoint target must be 'category/event'");
            return;
        }
        *slash = '\0';
        const char *tp_category = target;
        const char *tp_name = slash + 1;
        struct bpf_link *link = bpf_program__attach_tracepoint(prog, tp_category, tp_name);
        if (!link) {
            bpf_object__close(obj);
            loaded[slot].obj = NULL;
            char errbuf[128];
            snprintf(errbuf, sizeof(errbuf), "load: attach_tracepoint '%s/%s' failed: %s",
                     tp_category, tp_name, strerror(errno));
            send_error(errbuf);
            return;
        }
        loaded[slot].link = link;
        break;
    }
    case PROG_TYPE_RAW_TP: {
        struct bpf_link *link = bpf_program__attach_raw_tracepoint(prog, target);
        if (!link) {
            bpf_object__close(obj);
            loaded[slot].obj = NULL;
            char errbuf[128];
            snprintf(errbuf, sizeof(errbuf), "load: attach_raw_tracepoint '%s' failed: %s",
                     target, strerror(errno));
            send_error(errbuf);
            return;
        }
        loaded[slot].link = link;
        break;
    }
    case PROG_TYPE_TC: {
        /* target = interface name; attach as TC ingress classifier */
        unsigned int tc_ifindex = if_nametoindex(target);
        if (tc_ifindex == 0) {
            bpf_object__close(obj);
            loaded[slot].obj = NULL;
            char errbuf[128];
            snprintf(errbuf, sizeof(errbuf), "load: unknown interface '%s'", target);
            send_error(errbuf);
            return;
        }
        int prog_fd = bpf_program__fd(prog);
        if (prog_fd < 0) {
            bpf_object__close(obj);
            loaded[slot].obj = NULL;
            send_error("load: invalid program fd");
            return;
        }

        LIBBPF_OPTS(bpf_tc_hook, hook,
            .ifindex = tc_ifindex,
            .attach_point = BPF_TC_INGRESS,
        );
        /* Create clsact qdisc — EEXIST is fine (already exists) */
        int err = bpf_tc_hook_create(&hook);
        if (err && err != -EEXIST) {
            bpf_object__close(obj);
            loaded[slot].obj = NULL;
            char errbuf[128];
            snprintf(errbuf, sizeof(errbuf), "load: bpf_tc_hook_create failed: %s",
                     strerror(-err));
            send_error(errbuf);
            return;
        }

        LIBBPF_OPTS(bpf_tc_opts, tc_opts,
            .prog_fd = prog_fd,
        );
        err = bpf_tc_hook_attach(&hook, &tc_opts);
        if (err) {
            bpf_tc_hook_destroy(&hook);
            bpf_object__close(obj);
            loaded[slot].obj = NULL;
            char errbuf[128];
            snprintf(errbuf, sizeof(errbuf), "load: bpf_tc_hook_attach failed: %s",
                     strerror(-err));
            send_error(errbuf);
            return;
        }

        /* Save hook for cleanup — heap-allocate since LIBBPF_OPTS is stack-local */
        struct bpf_tc_hook *saved_hook = malloc(sizeof(struct bpf_tc_hook));
        if (!saved_hook) {
            /* Treat allocation failure as load failure */
            bpf_tc_hook_detach(&hook, &tc_opts);
            bpf_tc_hook_destroy(&hook);
            bpf_object__close(obj);
            loaded[slot].obj = NULL;
            send_error("load: failed to allocate memory for tc_hook state");
            return;
        }
        memcpy(saved_hook, &hook, sizeof(struct bpf_tc_hook));
        loaded[slot].tc_hook = saved_hook;
        loaded[slot].ifindex = tc_ifindex;
        break;
    }
    case PROG_TYPE_SOCKET_FILTER: {
        /* Create a raw socket and attach the BPF program via SO_ATTACH_BPF */
        int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
        if (sock < 0) {
            bpf_object__close(obj);
            loaded[slot].obj = NULL;
            char errbuf[128];
            snprintf(errbuf, sizeof(errbuf), "load: socket() failed: %s", strerror(errno));
            send_error(errbuf);
            return;
        }
        int prog_fd = bpf_program__fd(prog);
        if (setsockopt(sock, SOL_SOCKET, SO_ATTACH_BPF, &prog_fd, sizeof(prog_fd)) < 0) {
            close(sock);
            bpf_object__close(obj);
            loaded[slot].obj = NULL;
            char errbuf[128];
            snprintf(errbuf, sizeof(errbuf), "load: SO_ATTACH_BPF failed: %s", strerror(errno));
            send_error(errbuf);
            return;
        }
        loaded[slot].socket_fd = sock;
        break;
    }
    case PROG_TYPE_CGROUP_SKB:
    case PROG_TYPE_CGROUP_SOCK:
    case PROG_TYPE_CGROUP_SOCK_ADDR: {
        /* target = cgroup path (e.g. "/sys/fs/cgroup/unified") */
        int cg_fd = open(target, O_RDONLY);
        if (cg_fd < 0) {
            bpf_object__close(obj);
            loaded[slot].obj = NULL;
            char errbuf[128];
            snprintf(errbuf, sizeof(errbuf), "load: open cgroup '%s' failed: %s",
                     target, strerror(errno));
            send_error(errbuf);
            return;
        }
        struct bpf_link *link = bpf_program__attach_cgroup(prog, cg_fd);
        if (!link) {
            close(cg_fd);
            bpf_object__close(obj);
            loaded[slot].obj = NULL;
            char errbuf[128];
            snprintf(errbuf, sizeof(errbuf), "load: attach_cgroup '%s' failed: %s",
                     target, strerror(errno));
            send_error(errbuf);
            return;
        }
        loaded[slot].link = link;
        loaded[slot].cgroup_fd = cg_fd;
        break;
    }
    case PROG_TYPE_UPROBE:
    case PROG_TYPE_URETPROBE: {
        /* target format: "pid:binary_path:func_offset" */
        char *first_colon = strchr(target, ':');
        if (!first_colon) {
            bpf_object__close(obj);
            loaded[slot].obj = NULL;
            send_error("load: uprobe target must be 'pid:binary_path:offset'");
            return;
        }
        *first_colon = '\0';
        int pid = atoi(target);
        /* pid -1 means attach to all processes */
        if (pid == 0 && target[0] != '0') pid = -1;

        char *binary_path = first_colon + 1;
        char *second_colon = strrchr(binary_path, ':');
        if (!second_colon) {
            bpf_object__close(obj);
            loaded[slot].obj = NULL;
            send_error("load: uprobe target must be 'pid:binary_path:offset'");
            return;
        }
        *second_colon = '\0';
        size_t func_offset = (size_t)strtoul(second_colon + 1, NULL, 0);

        int is_retprobe = (prog_type == PROG_TYPE_URETPROBE);
        struct bpf_link *link = bpf_program__attach_uprobe(
            prog, is_retprobe, pid, binary_path, func_offset);
        if (!link) {
            bpf_object__close(obj);
            loaded[slot].obj = NULL;
            char errbuf[128];
            snprintf(errbuf, sizeof(errbuf), "load: attach_uprobe '%s' offset %zu failed: %s",
                     binary_path, func_offset, strerror(errno));
            send_error(errbuf);
            return;
        }
        loaded[slot].link = link;
        break;
    }
    case PROG_TYPE_PERF_EVENT: {
        /* target format: "type:config" (e.g. "1:1" for PERF_TYPE_SOFTWARE:PERF_COUNT_SW_CPU_CLOCK) */
        char *colon = strchr(target, ':');
        if (!colon) {
            bpf_object__close(obj);
            loaded[slot].obj = NULL;
            send_error("load: perf_event target must be 'type:config'");
            return;
        }
        *colon = '\0';
        uint32_t pe_type = (uint32_t)strtoul(target, NULL, 0);
        uint64_t pe_config = (uint64_t)strtoull(colon + 1, NULL, 0);

        struct perf_event_attr attr = {};
        attr.type = pe_type;
        attr.size = sizeof(attr);
        attr.config = pe_config;
        attr.sample_period = 1;

        /* Open perf event on cpu 0, pid=-1 for system-wide */
        int pe_fd = syscall(__NR_perf_event_open, &attr, -1 /* pid */, 0 /* cpu */, -1, 0);
        if (pe_fd < 0) {
            bpf_object__close(obj);
            loaded[slot].obj = NULL;
            char errbuf[128];
            snprintf(errbuf, sizeof(errbuf), "load: perf_event_open failed: %s", strerror(errno));
            send_error(errbuf);
            return;
        }

        struct bpf_link *link = bpf_program__attach_perf_event(prog, pe_fd);
        if (!link) {
            close(pe_fd);
            bpf_object__close(obj);
            loaded[slot].obj = NULL;
            char errbuf[128];
            snprintf(errbuf, sizeof(errbuf), "load: attach_perf_event failed: %s", strerror(errno));
            send_error(errbuf);
            return;
        }
        loaded[slot].link = link;
        loaded[slot].pe_fd = pe_fd;
        break;
    }
    case PROG_TYPE_LSM: {
        /* LSM programs get their attach point from the ELF section name */
        struct bpf_link *link = bpf_program__attach_lsm(prog);
        if (!link) {
            bpf_object__close(obj);
            loaded[slot].obj = NULL;
            char errbuf[128];
            snprintf(errbuf, sizeof(errbuf), "load: attach_lsm failed: %s", strerror(errno));
            send_error(errbuf);
            return;
        }
        loaded[slot].link = link;
        break;
    }
    case PROG_TYPE_STRUCT_OPS: {
        /* struct_ops programs auto-register from the ELF section */
        struct bpf_map *map;
        bpf_object__for_each_map(map, obj) {
            if (bpf_map__type(map) == BPF_MAP_TYPE_STRUCT_OPS) {
                struct bpf_link *link = bpf_map__attach_struct_ops(map);
                if (!link) {
                    bpf_object__close(obj);
                    loaded[slot].obj = NULL;
                    char errbuf[128];
                    snprintf(errbuf, sizeof(errbuf), "load: attach_struct_ops failed: %s",
                             strerror(errno));
                    send_error(errbuf);
                    return;
                }
                loaded[slot].link = link;
                break;
            }
        }
        break;
    }
    case PROG_TYPE_SK_MSG:
    case PROG_TYPE_SK_SKB:
    case PROG_TYPE_FLOW_DISSECTOR: {
        bpf_object__close(obj);
        loaded[slot].obj = NULL;
        char errbuf[128];
        snprintf(errbuf, sizeof(errbuf),
                 "load: prog_type %d requires sockmap/flow_dissector attach (not yet supported)",
                 prog_type);
        send_error(errbuf);
        return;
    }
    default: {
        bpf_object__close(obj);
        loaded[slot].obj = NULL;
        char errbuf[128];
        snprintf(errbuf, sizeof(errbuf), "load: unknown prog_type %d", prog_type);
        send_error(errbuf);
        return;
    }
    }

    send_load_ok(slot, obj);
}

static void handle_detach(const uint8_t *data, uint16_t len) {
    if (len < 4) { send_error("detach: frame too short"); return; }

    uint32_t handle = read_le32(data);
    if (handle >= MAX_OBJECTS || !loaded[handle].obj) {
        send_error("detach: invalid handle");
        return;
    }

    /* Detach based on how the program was attached */
    if (loaded[handle].link) {
        bpf_link__destroy(loaded[handle].link);
        loaded[handle].link = NULL;
    }
    if (loaded[handle].tc_hook) {
        bpf_tc_hook_destroy(loaded[handle].tc_hook);
        free(loaded[handle].tc_hook);
        loaded[handle].tc_hook = NULL;
    }
    if (loaded[handle].ifindex && loaded[handle].prog_type == PROG_TYPE_XDP) {
        bpf_xdp_detach(loaded[handle].ifindex, loaded[handle].xdp_flags, NULL);
    }
    loaded[handle].ifindex = 0;
    if (loaded[handle].cgroup_fd >= 0) {
        close(loaded[handle].cgroup_fd);
        loaded[handle].cgroup_fd = -1;
    }
    if (loaded[handle].socket_fd >= 0) {
        close(loaded[handle].socket_fd);
        loaded[handle].socket_fd = -1;
    }
    if (loaded[handle].pe_fd >= 0) {
        close(loaded[handle].pe_fd);
        loaded[handle].pe_fd = -1;
    }
    bpf_object__close(loaded[handle].obj);
    loaded[handle].obj = NULL;
    loaded[handle].prog_type = 0;

    uint8_t resp[1] = { RESP_OK };
    write_frame(resp, 1);
}

/* --- Map helpers --- */

/* Find a bpf_map by handle + name. Returns NULL on error, sets *map_out. */
static struct bpf_map *find_map(uint32_t handle, const char *map_name) {
    if (handle >= MAX_OBJECTS || !loaded[handle].obj) return NULL;
    return bpf_object__find_map_by_name(loaded[handle].obj, map_name);
}

/*
 * Parse [handle:4LE][name_len:1][name:N] from the front of a buffer.
 * Returns 0 on success, -1 on parse error.
 * Sets *handle_out, fills name_out (null-terminated), and advances
 * *rest / *rest_len past the consumed bytes.
 */
static int parse_handle_and_map(const uint8_t *data, uint16_t len,
                                uint32_t *handle_out, char *name_out,
                                const uint8_t **rest, uint16_t *rest_len) {
    if (len < 5) return -1;  /* handle(4) + name_len(1) */
    *handle_out = read_le32(data);
    uint8_t name_len = data[4];
    if (name_len == 0 || name_len > 255) return -1;
    if (len < 5 + (uint16_t)name_len) return -1;
    memcpy(name_out, data + 5, name_len);
    name_out[name_len] = '\0';
    *rest = data + 5 + name_len;
    *rest_len = len - 5 - name_len;
    return 0;
}

static void handle_map_lookup(const uint8_t *data, uint16_t len) {
    uint32_t handle;
    char map_name[256];
    const uint8_t *rest;
    uint16_t rest_len;

    if (parse_handle_and_map(data, len, &handle, map_name, &rest, &rest_len) < 0) {
        send_error("map_lookup: parse error");
        return;
    }

    /* Parse key */
    if (rest_len < 4) { send_error("map_lookup: missing key_len"); return; }
    uint32_t key_len = read_le32(rest);
    if (rest_len < 4 + key_len) { send_error("map_lookup: truncated key"); return; }
    const uint8_t *key = rest + 4;

    struct bpf_map *map = find_map(handle, map_name);
    if (!map) { send_error("map_lookup: map not found"); return; }

    int fd = bpf_map__fd(map);
    if (fd < 0) { send_error("map_lookup: bad map fd"); return; }

    uint32_t val_size = bpf_map__value_size(map);
    if (val_size > UINT16_MAX - 5) { send_error("map_lookup: value too large"); return; }
    uint8_t *value_buf = malloc(val_size);
    if (!value_buf) { send_error("map_lookup: alloc failed"); return; }

    if (bpf_map_lookup_elem(fd, key, value_buf) == 0) {
        /* Found: [0x00][val_len:4LE][value:N] */
        uint16_t resp_len = (uint16_t)(1 + 4 + val_size);
        uint8_t *resp = malloc(resp_len);
        if (!resp) { free(value_buf); send_error("map_lookup: alloc resp failed"); return; }
        resp[0] = RESP_OK;
        write_le32(resp + 1, val_size);
        memcpy(resp + 5, value_buf, val_size);
        write_frame(resp, resp_len);
        free(resp);
    } else if (errno == ENOENT) {
        /* Not found: [0x02] */
        uint8_t resp[1] = { RESP_NOT_FOUND };
        write_frame(resp, 1);
    } else {
        char errbuf[128];
        snprintf(errbuf, sizeof(errbuf), "map_lookup: bpf_map_lookup_elem failed: %s",
                 strerror(errno));
        send_error(errbuf);
    }

    free(value_buf);
}

static void handle_map_update(const uint8_t *data, uint16_t len) {
    uint32_t handle;
    char map_name[256];
    const uint8_t *rest;
    uint16_t rest_len;

    if (parse_handle_and_map(data, len, &handle, map_name, &rest, &rest_len) < 0) {
        send_error("map_update: parse error");
        return;
    }

    /* Parse key */
    if (rest_len < 4) { send_error("map_update: missing key_len"); return; }
    uint32_t key_len = read_le32(rest);
    if (rest_len < 4 + key_len) { send_error("map_update: truncated key"); return; }
    const uint8_t *key = rest + 4;
    rest += 4 + key_len;
    rest_len -= 4 + key_len;

    /* Parse value */
    if (rest_len < 4) { send_error("map_update: missing val_len"); return; }
    uint32_t val_len = read_le32(rest);
    if (rest_len < 4 + val_len) { send_error("map_update: truncated value"); return; }
    const uint8_t *value = rest + 4;
    rest += 4 + val_len;
    rest_len -= 4 + val_len;

    /* Parse flags */
    if (rest_len < 4) { send_error("map_update: missing flags"); return; }
    uint32_t flags = read_le32(rest);

    struct bpf_map *map = find_map(handle, map_name);
    if (!map) { send_error("map_update: map not found"); return; }

    int fd = bpf_map__fd(map);
    if (fd < 0) { send_error("map_update: bad map fd"); return; }

    if (bpf_map_update_elem(fd, key, value, flags) == 0) {
        uint8_t resp[1] = { RESP_OK };
        write_frame(resp, 1);
    } else {
        char errbuf[128];
        snprintf(errbuf, sizeof(errbuf), "map_update: bpf_map_update_elem failed: %s",
                 strerror(errno));
        send_error(errbuf);
    }
}

static void handle_map_delete(const uint8_t *data, uint16_t len) {
    uint32_t handle;
    char map_name[256];
    const uint8_t *rest;
    uint16_t rest_len;

    if (parse_handle_and_map(data, len, &handle, map_name, &rest, &rest_len) < 0) {
        send_error("map_delete: parse error");
        return;
    }

    /* Parse key */
    if (rest_len < 4) { send_error("map_delete: missing key_len"); return; }
    uint32_t key_len = read_le32(rest);
    if (rest_len < 4 + key_len) { send_error("map_delete: truncated key"); return; }
    const uint8_t *key = rest + 4;

    struct bpf_map *map = find_map(handle, map_name);
    if (!map) { send_error("map_delete: map not found"); return; }

    int fd = bpf_map__fd(map);
    if (fd < 0) { send_error("map_delete: bad map fd"); return; }

    if (bpf_map_delete_elem(fd, key) == 0) {
        uint8_t resp[1] = { RESP_OK };
        write_frame(resp, 1);
    } else if (errno == ENOENT) {
        uint8_t resp[1] = { RESP_NOT_FOUND };
        write_frame(resp, 1);
    } else {
        char errbuf[128];
        snprintf(errbuf, sizeof(errbuf), "map_delete: bpf_map_delete_elem failed: %s",
                 strerror(errno));
        send_error(errbuf);
    }
}

static void handle_map_get_next_key(const uint8_t *data, uint16_t len) {
    uint32_t handle;
    char map_name[256];
    const uint8_t *rest;
    uint16_t rest_len;

    if (parse_handle_and_map(data, len, &handle, map_name, &rest, &rest_len) < 0) {
        send_error("map_get_next_key: parse error");
        return;
    }

    /* Parse key_len and optional key (key_len=0 means "get first key") */
    if (rest_len < 4) { send_error("map_get_next_key: missing key_len"); return; }
    uint32_t key_len = read_le32(rest);
    if (rest_len < 4 + key_len) { send_error("map_get_next_key: truncated key"); return; }
    const uint8_t *key = (key_len > 0) ? (rest + 4) : NULL;

    struct bpf_map *map = find_map(handle, map_name);
    if (!map) { send_error("map_get_next_key: map not found"); return; }

    int fd = bpf_map__fd(map);
    if (fd < 0) { send_error("map_get_next_key: bad map fd"); return; }

    uint32_t map_key_size = bpf_map__key_size(map);
    if (map_key_size > UINT16_MAX - 5) { send_error("map_get_next_key: key too large"); return; }
    uint8_t *next_key = malloc(map_key_size);
    if (!next_key) { send_error("map_get_next_key: alloc failed"); return; }

    if (bpf_map_get_next_key(fd, key, next_key) == 0) {
        /* Found: [0x00][key_len:4LE][next_key:N] */
        uint16_t resp_len = (uint16_t)(1 + 4 + map_key_size);
        uint8_t *resp = malloc(resp_len);
        if (!resp) { free(next_key); send_error("map_get_next_key: alloc resp failed"); return; }
        resp[0] = RESP_OK;
        write_le32(resp + 1, map_key_size);
        memcpy(resp + 5, next_key, map_key_size);
        write_frame(resp, resp_len);
        free(resp);
    } else if (errno == ENOENT) {
        /* No more keys: [0x02] */
        uint8_t resp[1] = { RESP_NOT_FOUND };
        write_frame(resp, 1);
    } else {
        char errbuf[128];
        snprintf(errbuf, sizeof(errbuf), "map_get_next_key: failed: %s", strerror(errno));
        send_error(errbuf);
    }

    free(next_key);
}

/* --- Ring buffer event callback --- */

static int ringbuf_event_cb(void *ctx, void *data, size_t data_sz) {
    struct rb_sub *sub = ctx;
    uint8_t name_len = (uint8_t)strlen(sub->map_name);

    /* Build: [0x10][handle:4LE][name_len:1][name:N][data_len:4LE][data:N] */
    size_t base_len = 1 + 4 + 1 + (size_t)name_len + 4;
    if (data_sz > 65535 - base_len) return 0;  /* too large for {:packet, 2} framing */
    uint32_t frame_len = (uint32_t)(base_len + data_sz);

    uint8_t *buf = malloc(frame_len);
    if (!buf) return 0;

    uint32_t pos = 0;
    buf[pos++] = RESP_RINGBUF_EVENT;
    write_le32(buf + pos, sub->handle);
    pos += 4;
    buf[pos++] = name_len;
    memcpy(buf + pos, sub->map_name, name_len);
    pos += name_len;
    write_le32(buf + pos, (uint32_t)data_sz);
    pos += 4;
    memcpy(buf + pos, data, data_sz);
    pos += (uint32_t)data_sz;

    write_frame(buf, (uint16_t)frame_len);
    free(buf);
    return 0;
}

/* --- Ring buffer subscribe/unsubscribe --- */

static void handle_subscribe_ringbuf(const uint8_t *data, uint16_t len) {
    uint32_t handle;
    char map_name[256];
    const uint8_t *rest;
    uint16_t rest_len;

    if (parse_handle_and_map(data, len, &handle, map_name, &rest, &rest_len) < 0) {
        send_error("subscribe_ringbuf: parse error");
        return;
    }

    if (num_ringbufs >= MAX_RINGBUFS) {
        send_error("subscribe_ringbuf: too many ring buffer subscriptions");
        return;
    }

    struct bpf_map *map = find_map(handle, map_name);
    if (!map) {
        send_error("subscribe_ringbuf: map not found");
        return;
    }

    int map_fd = bpf_map__fd(map);
    if (map_fd < 0) {
        send_error("subscribe_ringbuf: bad map fd");
        return;
    }

    /* Validate name fits in rb_sub */
    if (strlen(map_name) >= sizeof(ringbufs[0].map_name)) {
        send_error("subscribe_ringbuf: map name too long");
        return;
    }

    /* Set up the subscription entry before creating the ring buffer,
     * because the callback uses it as context. */
    int idx = num_ringbufs;
    ringbufs[idx].handle = handle;
    strncpy(ringbufs[idx].map_name, map_name, sizeof(ringbufs[idx].map_name) - 1);
    ringbufs[idx].map_name[sizeof(ringbufs[idx].map_name) - 1] = '\0';
    ringbufs[idx].rb = NULL;
    ringbufs[idx].epoll_fd_val = -1;

    struct ring_buffer *rb = ring_buffer__new(map_fd, ringbuf_event_cb, &ringbufs[idx], NULL);
    if (!rb) {
        char errbuf[128];
        snprintf(errbuf, sizeof(errbuf), "subscribe_ringbuf: ring_buffer__new failed: %s",
                 strerror(errno));
        send_error(errbuf);
        return;
    }

    int rb_fd = ring_buffer__epoll_fd(rb);
    if (rb_fd < 0) {
        ring_buffer__free(rb);
        send_error("subscribe_ringbuf: ring_buffer__epoll_fd failed");
        return;
    }

    /* Add ring buffer fd to epoll set */
    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.ptr = &ringbufs[idx];
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, rb_fd, &ev) < 0) {
        ring_buffer__free(rb);
        char errbuf[128];
        snprintf(errbuf, sizeof(errbuf), "subscribe_ringbuf: epoll_ctl ADD failed: %s",
                 strerror(errno));
        send_error(errbuf);
        return;
    }

    ringbufs[idx].rb = rb;
    ringbufs[idx].epoll_fd_val = rb_fd;
    num_ringbufs++;

    uint8_t resp[1] = { RESP_OK };
    write_frame(resp, 1);
}

static void handle_unsubscribe_ringbuf(const uint8_t *data, uint16_t len) {
    uint32_t handle;
    char map_name[256];
    const uint8_t *rest;
    uint16_t rest_len;

    if (parse_handle_and_map(data, len, &handle, map_name, &rest, &rest_len) < 0) {
        send_error("unsubscribe_ringbuf: parse error");
        return;
    }

    /* Find matching subscription */
    int found = -1;
    for (int i = 0; i < num_ringbufs; i++) {
        if (ringbufs[i].handle == handle && strcmp(ringbufs[i].map_name, map_name) == 0) {
            found = i;
            break;
        }
    }

    if (found < 0) {
        send_error("unsubscribe_ringbuf: subscription not found");
        return;
    }

    /* Remove from epoll */
    epoll_ctl(epoll_fd, EPOLL_CTL_DEL, ringbufs[found].epoll_fd_val, NULL);

    /* Free ring buffer */
    ring_buffer__free(ringbufs[found].rb);

    /* Compact array: move last entry into the gap */
    num_ringbufs--;
    if (found < num_ringbufs) {
        ringbufs[found] = ringbufs[num_ringbufs];
    }
    memset(&ringbufs[num_ringbufs], 0, sizeof(struct rb_sub));

    uint8_t resp[1] = { RESP_OK };
    write_frame(resp, 1);
}

/* --- Perf buffer event callbacks --- */

static void perfbuf_sample_cb(void *ctx, int cpu, void *data, __u32 data_sz) {
    struct pb_sub *sub = ctx;
    uint8_t name_len = (uint8_t)strlen(sub->map_name);

    /* Build: [0x11][handle:4LE][name_len:1][name:N][data_len:4LE][data:N] */
    size_t base_len = 1 + 4 + 1 + (size_t)name_len + 4;
    if (data_sz > 65535 - base_len) return;  /* too large for {:packet, 2} framing */
    uint32_t frame_len = (uint32_t)(base_len + data_sz);

    uint8_t *buf = malloc(frame_len);
    if (!buf) return;

    uint32_t pos = 0;
    buf[pos++] = RESP_PERFBUF_EVENT;
    write_le32(buf + pos, sub->handle);
    pos += 4;
    buf[pos++] = name_len;
    memcpy(buf + pos, sub->map_name, name_len);
    pos += name_len;
    write_le32(buf + pos, data_sz);
    pos += 4;
    memcpy(buf + pos, data, data_sz);
    pos += data_sz;

    write_frame(buf, (uint16_t)frame_len);
    free(buf);
}

static void perfbuf_lost_cb(void *ctx, int cpu, __u64 lost_cnt) {
    struct pb_sub *sub = ctx;
    uint8_t name_len = (uint8_t)strlen(sub->map_name);

    /* Build: [0x12][handle:4LE][name_len:1][name:N][lost_count:8LE] */
    uint32_t frame_len = 1 + 4 + 1 + (uint32_t)name_len + 8;

    uint8_t *buf = malloc(frame_len);
    if (!buf) return;

    uint32_t pos = 0;
    buf[pos++] = RESP_PERFBUF_LOST;
    write_le32(buf + pos, sub->handle);
    pos += 4;
    buf[pos++] = name_len;
    memcpy(buf + pos, sub->map_name, name_len);
    pos += name_len;
    /* Write lost_count as u64 LE */
    buf[pos++] = (uint8_t)(lost_cnt);
    buf[pos++] = (uint8_t)(lost_cnt >> 8);
    buf[pos++] = (uint8_t)(lost_cnt >> 16);
    buf[pos++] = (uint8_t)(lost_cnt >> 24);
    buf[pos++] = (uint8_t)(lost_cnt >> 32);
    buf[pos++] = (uint8_t)(lost_cnt >> 40);
    buf[pos++] = (uint8_t)(lost_cnt >> 48);
    buf[pos++] = (uint8_t)(lost_cnt >> 56);

    write_frame(buf, (uint16_t)frame_len);
    free(buf);
}

/* --- Perf buffer subscribe/unsubscribe --- */

static void handle_subscribe_perfbuf(const uint8_t *data, uint16_t len) {
    uint32_t handle;
    char map_name[256];
    const uint8_t *rest;
    uint16_t rest_len;

    if (parse_handle_and_map(data, len, &handle, map_name, &rest, &rest_len) < 0) {
        send_error("subscribe_perfbuf: parse error");
        return;
    }

    if (num_perfbufs >= MAX_PERFBUFS) {
        send_error("subscribe_perfbuf: too many perf buffer subscriptions");
        return;
    }

    struct bpf_map *map = find_map(handle, map_name);
    if (!map) {
        send_error("subscribe_perfbuf: map not found");
        return;
    }

    int map_fd = bpf_map__fd(map);
    if (map_fd < 0) {
        send_error("subscribe_perfbuf: bad map fd");
        return;
    }

    if (strlen(map_name) >= sizeof(perfbufs[0].map_name)) {
        send_error("subscribe_perfbuf: map name too long");
        return;
    }

    int idx = num_perfbufs;
    perfbufs[idx].handle = handle;
    strncpy(perfbufs[idx].map_name, map_name, sizeof(perfbufs[idx].map_name) - 1);
    perfbufs[idx].map_name[sizeof(perfbufs[idx].map_name) - 1] = '\0';
    perfbufs[idx].pb = NULL;
    perfbufs[idx].epoll_fd_val = -1;

    struct perf_buffer *pb = perf_buffer__new(map_fd, 8,
        perfbuf_sample_cb, perfbuf_lost_cb, &perfbufs[idx], NULL);
    if (!pb) {
        char errbuf[128];
        snprintf(errbuf, sizeof(errbuf), "subscribe_perfbuf: perf_buffer__new failed: %s",
                 strerror(errno));
        send_error(errbuf);
        return;
    }

    int pb_fd = perf_buffer__epoll_fd(pb);
    if (pb_fd < 0) {
        perf_buffer__free(pb);
        send_error("subscribe_perfbuf: perf_buffer__epoll_fd failed");
        return;
    }

    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.ptr = &perfbufs[idx];
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, pb_fd, &ev) < 0) {
        perf_buffer__free(pb);
        char errbuf[128];
        snprintf(errbuf, sizeof(errbuf), "subscribe_perfbuf: epoll_ctl ADD failed: %s",
                 strerror(errno));
        send_error(errbuf);
        return;
    }

    perfbufs[idx].pb = pb;
    perfbufs[idx].epoll_fd_val = pb_fd;
    num_perfbufs++;

    uint8_t resp[1] = { RESP_OK };
    write_frame(resp, 1);
}

static void handle_unsubscribe_perfbuf(const uint8_t *data, uint16_t len) {
    uint32_t handle;
    char map_name[256];
    const uint8_t *rest;
    uint16_t rest_len;

    if (parse_handle_and_map(data, len, &handle, map_name, &rest, &rest_len) < 0) {
        send_error("unsubscribe_perfbuf: parse error");
        return;
    }

    int found = -1;
    for (int i = 0; i < num_perfbufs; i++) {
        if (perfbufs[i].handle == handle && strcmp(perfbufs[i].map_name, map_name) == 0) {
            found = i;
            break;
        }
    }

    if (found < 0) {
        send_error("unsubscribe_perfbuf: subscription not found");
        return;
    }

    epoll_ctl(epoll_fd, EPOLL_CTL_DEL, perfbufs[found].epoll_fd_val, NULL);
    perf_buffer__free(perfbufs[found].pb);

    num_perfbufs--;
    if (found < num_perfbufs) {
        perfbufs[found] = perfbufs[num_perfbufs];
    }
    memset(&perfbufs[num_perfbufs], 0, sizeof(struct pb_sub));

    uint8_t resp[1] = { RESP_OK };
    write_frame(resp, 1);
}

/* --- Cleanup on exit --- */

static void cleanup_all(void) {
    /* Free all ring buffer subscriptions first */
    for (int i = 0; i < num_ringbufs; i++) {
        if (ringbufs[i].rb) {
            if (epoll_fd >= 0 && ringbufs[i].epoll_fd_val >= 0) {
                epoll_ctl(epoll_fd, EPOLL_CTL_DEL, ringbufs[i].epoll_fd_val, NULL);
            }
            ring_buffer__free(ringbufs[i].rb);
            ringbufs[i].rb = NULL;
        }
    }
    num_ringbufs = 0;

    /* Free all perf buffer subscriptions */
    for (int i = 0; i < num_perfbufs; i++) {
        if (perfbufs[i].pb) {
            if (epoll_fd >= 0 && perfbufs[i].epoll_fd_val >= 0) {
                epoll_ctl(epoll_fd, EPOLL_CTL_DEL, perfbufs[i].epoll_fd_val, NULL);
            }
            perf_buffer__free(perfbufs[i].pb);
            perfbufs[i].pb = NULL;
        }
    }
    num_perfbufs = 0;

    for (int i = 0; i < MAX_OBJECTS; i++) {
        if (loaded[i].obj) {
            if (loaded[i].link) {
                bpf_link__destroy(loaded[i].link);
                loaded[i].link = NULL;
            }
            if (loaded[i].tc_hook) {
                bpf_tc_hook_destroy(loaded[i].tc_hook);
                free(loaded[i].tc_hook);
                loaded[i].tc_hook = NULL;
            }
            if (loaded[i].ifindex && loaded[i].prog_type == PROG_TYPE_XDP) {
                bpf_xdp_detach(loaded[i].ifindex, loaded[i].xdp_flags, NULL);
            }
            loaded[i].ifindex = 0;
            if (loaded[i].cgroup_fd >= 0) {
                close(loaded[i].cgroup_fd);
                loaded[i].cgroup_fd = -1;
            }
            if (loaded[i].socket_fd >= 0) {
                close(loaded[i].socket_fd);
                loaded[i].socket_fd = -1;
            }
            if (loaded[i].pe_fd >= 0) {
                close(loaded[i].pe_fd);
                loaded[i].pe_fd = -1;
            }
            bpf_object__close(loaded[i].obj);
            loaded[i].obj = NULL;
        }
    }

    if (epoll_fd >= 0) {
        close(epoll_fd);
        epoll_fd = -1;
    }
}

/* --- Dispatch a single command frame --- */

static void dispatch_command(uint8_t *frame, uint16_t frame_len) {
    if (frame_len < 1) return;

    uint8_t cmd = frame[0];
    const uint8_t *payload = frame + 1;
    uint16_t payload_len = frame_len - 1;

    switch (cmd) {
    case CMD_LOAD_XDP:
        handle_load_xdp(payload, payload_len);
        break;
    case CMD_DETACH:
        handle_detach(payload, payload_len);
        break;
    case CMD_MAP_LOOKUP:
        handle_map_lookup(payload, payload_len);
        break;
    case CMD_MAP_UPDATE:
        handle_map_update(payload, payload_len);
        break;
    case CMD_MAP_DELETE:
        handle_map_delete(payload, payload_len);
        break;
    case CMD_SUBSCRIBE_RINGBUF:
        handle_subscribe_ringbuf(payload, payload_len);
        break;
    case CMD_UNSUBSCRIBE_RINGBUF:
        handle_unsubscribe_ringbuf(payload, payload_len);
        break;
    case CMD_MAP_GET_NEXT_KEY:
        handle_map_get_next_key(payload, payload_len);
        break;
    case CMD_LOAD:
        handle_load(payload, payload_len);
        break;
    case CMD_SUBSCRIBE_PERFBUF:
        handle_subscribe_perfbuf(payload, payload_len);
        break;
    case CMD_UNSUBSCRIBE_PERFBUF:
        handle_unsubscribe_perfbuf(payload, payload_len);
        break;
    default: {
        char errbuf[64];
        snprintf(errbuf, sizeof(errbuf), "unknown command: 0x%02x", cmd);
        send_error(errbuf);
        break;
    }
    }
}

/* --- Main loop (epoll-based) --- */

int main(void) {
    memset(loaded, 0, sizeof(loaded));
    memset(ringbufs, 0, sizeof(ringbufs));
    memset(perfbufs, 0, sizeof(perfbufs));

    /* Create epoll instance */
    epoll_fd = epoll_create1(0);
    if (epoll_fd < 0) {
        /* Fatal — can't run without epoll */
        return 1;
    }

    /* Add stdin to epoll set */
    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.ptr = EPOLL_STDIN_PTR;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, STDIN_FILENO, &ev) < 0) {
        close(epoll_fd);
        return 1;
    }

    /* Event loop: wait on stdin + ring buffer + perf buffer fds */
    struct epoll_event events[MAX_RINGBUFS + MAX_PERFBUFS + 1];
    int running = 1;

    while (running) {
        int nfds = epoll_wait(epoll_fd, events, MAX_RINGBUFS + MAX_PERFBUFS + 1, -1);
        if (nfds < 0) {
            if (errno == EINTR) continue;
            break;
        }

        for (int i = 0; i < nfds; i++) {
            if (events[i].data.ptr == EPOLL_STDIN_PTR) {
                /* stdin ready — read and dispatch a command frame */
                uint8_t *frame;
                uint16_t frame_len;
                if (read_frame(&frame, &frame_len) < 0) {
                    running = 0;
                    break;
                }
                dispatch_command(frame, frame_len);
                free(frame);
            } else if (events[i].data.ptr >= (void *)perfbufs &&
                       events[i].data.ptr < (void *)(perfbufs + MAX_PERFBUFS)) {
                /* Perf buffer fd ready — consume events (fires sample + lost callbacks) */
                struct pb_sub *sub = events[i].data.ptr;
                if (sub && sub->pb) {
                    perf_buffer__consume(sub->pb);
                }
            } else {
                /* Ring buffer fd ready — consume events (fires callback) */
                struct rb_sub *sub = events[i].data.ptr;
                if (sub && sub->rb) {
                    ring_buffer__consume(sub->rb);
                }
            }
        }
    }

    cleanup_all();
    return 0;
}
