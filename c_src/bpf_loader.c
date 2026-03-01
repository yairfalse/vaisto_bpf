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
#include <sys/epoll.h>

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

#define RESP_OK        0x00
#define RESP_ERROR     0x01
#define RESP_NOT_FOUND 0x02
#define RESP_RINGBUF_EVENT 0x10

#define MAX_OBJECTS  16
#define MAX_RESP     4096
#define MAX_IFACE    64
#define MAX_RINGBUFS 8

struct loaded_obj {
    struct bpf_object *obj;
    unsigned int ifindex;
    uint32_t xdp_flags;
};

struct rb_sub {
    struct ring_buffer *rb;
    uint32_t handle;
    char map_name[64];
    int epoll_fd_val;   /* cached fd for epoll removal */
};

static struct loaded_obj loaded[MAX_OBJECTS];
static struct rb_sub ringbufs[MAX_RINGBUFS];
static int num_ringbufs = 0;
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
    loaded[slot].ifindex = ifindex;
    loaded[slot].xdp_flags = xdp_flags;

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

static void handle_detach(const uint8_t *data, uint16_t len) {
    if (len < 4) { send_error("detach: frame too short"); return; }

    uint32_t handle = read_le32(data);
    if (handle >= MAX_OBJECTS || !loaded[handle].obj) {
        send_error("detach: invalid handle");
        return;
    }

    bpf_xdp_detach(loaded[handle].ifindex, loaded[handle].xdp_flags, NULL);
    bpf_object__close(loaded[handle].obj);
    loaded[handle].obj = NULL;
    loaded[handle].ifindex = 0;

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

    for (int i = 0; i < MAX_OBJECTS; i++) {
        if (loaded[i].obj) {
            bpf_xdp_detach(loaded[i].ifindex, loaded[i].xdp_flags, NULL);
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

    /* Event loop: wait on stdin + ring buffer fds */
    struct epoll_event events[MAX_RINGBUFS + 1];
    int running = 1;

    while (running) {
        int nfds = epoll_wait(epoll_fd, events, MAX_RINGBUFS + 1, -1);
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
