/*
 * bpf_loader.c — Erlang port for loading BPF programs via libbpf.
 *
 * Protocol: {:packet, 2} framing (2-byte big-endian length prefix).
 * Data integers are little-endian.
 *
 * Commands:
 *   LOAD_XDP (0x01): [0x01][elf_size:4LE][elf:N][iface_len:1][iface:N]
 *   DETACH   (0x02): [0x02][handle:4LE]
 *
 * Responses:
 *   OK (load): [0x00][handle:4LE][num_maps:1]([name_len:1][name:N])*
 *   OK (detach): [0x00]
 *   ERROR:    [0x01][message...]
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

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#define CMD_LOAD_XDP 0x01
#define CMD_DETACH   0x02

#define RESP_OK    0x00
#define RESP_ERROR 0x01

#define MAX_OBJECTS 16
#define MAX_RESP    4096
#define MAX_IFACE   64

struct loaded_obj {
    struct bpf_object *obj;
    unsigned int ifindex;
    uint32_t xdp_flags;
};

static struct loaded_obj loaded[MAX_OBJECTS];

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
    if (len < 4 + elf_size + 1) { send_error("load_xdp: bad elf_size"); return; }

    const uint8_t *elf_data = data + 4;
    uint8_t iface_len = data[4 + elf_size];
    if (len < 4 + elf_size + 1 + iface_len) { send_error("load_xdp: bad iface_len"); return; }

    char iface[MAX_IFACE + 1];
    if (iface_len > MAX_IFACE) { send_error("load_xdp: interface name too long"); return; }
    memcpy(iface, data + 4 + elf_size + 1, iface_len);
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

/* --- Cleanup on exit --- */

static void cleanup_all(void) {
    for (int i = 0; i < MAX_OBJECTS; i++) {
        if (loaded[i].obj) {
            bpf_xdp_detach(loaded[i].ifindex, loaded[i].xdp_flags, NULL);
            bpf_object__close(loaded[i].obj);
            loaded[i].obj = NULL;
        }
    }
}

/* --- Main loop --- */

int main(void) {
    memset(loaded, 0, sizeof(loaded));

    uint8_t *frame;
    uint16_t frame_len;

    while (read_frame(&frame, &frame_len) == 0) {
        if (frame_len < 1) { free(frame); continue; }

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
        default: {
            char errbuf[64];
            snprintf(errbuf, sizeof(errbuf), "unknown command: 0x%02x", cmd);
            send_error(errbuf);
            break;
        }
        }

        free(frame);
    }

    cleanup_all();
    return 0;
}
