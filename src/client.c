#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <poll.h>
#include <arpa/inet.h>
#include <netpacket/packet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <net/if_arp.h>
#include <fcntl.h>
#include "protocol.h"
#include "encryption.h"

static const uint8_t PRE_SHARED_KEY[KEY_LENGTH] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
};

int ny_open(ny_handle_t* h, const char* iface) {
    LOG("INFO", "Opening raw socket on interface %s", iface);
    h->fd = socket(AF_PACKET, SOCK_RAW | SOCK_NONBLOCK, htons(NY_ETHERTYPE));
    if (h->fd < 0) {
        LOG("ERROR", "Socket creation failed: %s", strerror(errno));
        return -1;
    }
    LOG("DEBUG", "Raw socket created successfully, fd=%d", h->fd);

    h->ifindex = if_nametoindex(iface);
    if (!h->ifindex) {
        LOG("ERROR", "if_nametoindex failed for interface %s: %s", iface, strerror(errno));
        close(h->fd);
        return -1;
    }
    LOG("DEBUG", "Interface index retrieved: %d", h->ifindex);

    struct sockaddr_ll bindaddr = {0};
    bindaddr.sll_family = AF_PACKET;
    bindaddr.sll_ifindex = h->ifindex;
    bindaddr.sll_protocol = htons(NY_ETHERTYPE);
    if (bind(h->fd, (struct sockaddr*)&bindaddr, sizeof(bindaddr)) < 0) {
        LOG("ERROR", "Bind failed for interface %s: %s", iface, strerror(errno));
        close(h->fd);
        return -1;
    }
    LOG("DEBUG", "Socket bound to interface %s", iface);

    struct ifreq ifr = {0};
    strncpy(ifr.ifr_name, iface, IFNAMSIZ-1);
    if (ioctl(h->fd, SIOCGIFHWADDR, &ifr) < 0) {
        LOG("ERROR", "SIOCGIFHWADDR failed for interface %s: %s", iface, strerror(errno));
        close(h->fd);
        return -1;
    }
    memcpy(h->mac, ifr.ifr_hwaddr.sa_data, 6);
    LOG("DEBUG", "Retrieved MAC address for interface %s", iface);

    memcpy(h->key, PRE_SHARED_KEY, KEY_LENGTH);
    LOG("DEBUG", "Initialized with pre-shared key");

    LOG("INFO", "Local MAC address: %02x:%02x:%02x:%02x:%02x:%02x",
        h->mac[0], h->mac[1], h->mac[2], h->mac[3], h->mac[4], h->mac[5]);
    return 0;
}

ssize_t ny_send(ny_handle_t* h, const uint8_t dst[6], ny_hdr_t* hdr, const uint8_t* payload, size_t payload_len) {
    uint8_t frame[NY_MTU];
    struct ethhdr *eth = (struct ethhdr*)frame;
    memcpy(eth->h_dest, dst, 6);
    memcpy(eth->h_source, h->mac, 6);
    eth->h_proto = htons(NY_ETHERTYPE);
    LOG("DEBUG", "Prepared Ethernet header: dst=%02x:%02x:%02x:%02x:%02x:%02x src=%02x:%02x:%02x:%02x:%02x:%02x proto=0x%04x",
        eth->h_dest[0], eth->h_dest[1], eth->h_dest[2], eth->h_dest[3], eth->h_dest[4], eth->h_dest[5],
        eth->h_source[0], eth->h_source[1], eth->h_source[2], eth->h_source[3], eth->h_source[4], eth->h_source[5],
        ntohs(eth->h_proto));

    uint8_t encrypted[NY_MTU];
    size_t encrypted_len = 0;
    if (payload && payload_len && hdr->type == NY_DATA) {
        LOG("DEBUG", "Encrypting payload of %zu bytes", payload_len);
        if (encrypt_payload(h->key, hdr->iv, payload, payload_len, encrypted, &encrypted_len) < 0) {
            LOG("ERROR", "Payload encryption failed");
            return -1;
        }
        hdr->length = encrypted_len;
        LOG("DEBUG", "Payload encrypted, length=%u bytes", hdr->length);
    } else {
        hdr->length = 0;
        LOG("DEBUG", "No payload to encrypt for type=%d", hdr->type);
    }

    if (hdr->type == NY_DATA) {
        uint8_t hmac_data[NY_MTU];
        size_t hmac_data_len = sizeof(ny_hdr_t) - HMAC_LENGTH;
        memcpy(hmac_data, hdr, hmac_data_len);
        if (hdr->length) {
            memcpy(hmac_data + hmac_data_len, encrypted, hdr->length);
            hmac_data_len += hdr->length;
        }
        LOG("DEBUG", "Computing HMAC for %zu bytes of data", hmac_data_len);
        compute_hmac(h->key, hmac_data, hmac_data_len, hdr->hmac);
    } else {
        memset(hdr->hmac, 0, HMAC_LENGTH);
        LOG("DEBUG", "No HMAC computed for non-DATA frame type=%d", hdr->type);
    }

    memcpy(frame + sizeof(struct ethhdr), hdr, sizeof(*hdr));
    if (hdr->length) {
        memcpy(frame + sizeof(struct ethhdr) + sizeof(*hdr), encrypted, hdr->length);
    }
    LOG("DEBUG", "Frame constructed, total length=%zu bytes", sizeof(struct ethhdr) + sizeof(*hdr) + hdr->length);

    struct sockaddr_ll addr = {0};
    addr.sll_family = AF_PACKET;
    addr.sll_ifindex = h->ifindex;
    addr.sll_halen = 6;
    memcpy(addr.sll_addr, dst, 6);

    ssize_t len = sizeof(struct ethhdr) + sizeof(*hdr) + hdr->length;
    LOG("DEBUG", "Sending frame of %zd bytes", len);
    ssize_t ret = sendto(h->fd, frame, len, 0, (struct sockaddr*)&addr, sizeof(addr));
    if (ret < 0) {
        LOG("ERROR", "sendto failed: %s", strerror(errno));
    } else {
        LOG("DEBUG", "Sent %zd bytes successfully", ret);
    }
    return ret;
}

ssize_t ny_recv(ny_handle_t* h, uint8_t* buf, size_t len) {
    LOG("DEBUG", "Attempting to receive data, buffer size=%zu", len);
    ssize_t n = recv(h->fd, buf, len, 0);
    if (n > 0) {
        LOG("DEBUG", "Received %zd bytes", n);
    } else if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
        LOG("ERROR", "recv failed: %s", strerror(errno));
    } else {
        LOG("DEBUG", "No data received, errno=%d", errno);
    }
    return n;
}

void send_frame(ny_handle_t* h, const uint8_t dst[6], uint8_t type, uint32_t seq, const uint8_t mac[6], const char* msg) {
    ny_hdr_t hdr = {'N', 'Y', 0, type, 0, seq, {0}, time(NULL), {0}, {0}};
    memcpy(hdr.mac, mac, 6);
    if (type == NY_DATA && RAND_bytes(hdr.iv, IV_LENGTH) != 1) {
        LOG("ERROR", "Failed to generate IV for DATA frame");
        return;
    }
    if (type == NY_DATA) {
        LOG("DEBUG", "Generated IV for DATA frame");
    }
    size_t msg_len = msg ? strlen(msg) : 0;
    LOG("DEBUG", "Preparing to send frame: type=%d seq=%u MAC=%02x:%02x:%02x:%02x:%02x:%02x payload_len=%zu",
        type, seq, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], msg_len);
    ny_send(h, dst, &hdr, (const uint8_t*)msg, msg_len);
    LOG("INFO", "Sent frame: type=%d seq=%u MAC=%02x:%02x:%02x:%02x:%02x:%02x payload='%s'",
        type, seq, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], msg ? msg : "<none>");
}

int main(int argc, char** argv) {
    if (argc < 2) {
        LOG("ERROR", "Usage: %s <iface>", argv[0]);
        return 1;
    }
    const char* iface = argv[1];
    LOG("DEBUG", "Starting program with interface %s", iface);
    ny_handle_t* h = malloc(sizeof(ny_handle_t));
    if (!h) {
        LOG("ERROR", "Memory allocation failed for ny_handle_t");
        return 1;
    }
    LOG("DEBUG", "Allocated memory for ny_handle_t");

    if (ny_open(h, iface) < 0) {
        free(h);
        return 1;
    }
    LOG("DEBUG", "ny_open completed successfully");

    uint8_t bcast[6];
    memset(bcast, 0xff, 6);
    uint32_t seq = 1;

    LOG("INFO", "Sending DISCOVER frame");
    send_frame(h, bcast, NY_DISCOVER, seq++, h->mac, NULL);

    time_t start = time(NULL);
    uint8_t used[256][6] = {{0}};
    int used_count = 0;
    LOG("INFO", "Listening for ANNOUNCE frames for 5 seconds");
    while (time(NULL) - start < 5) {
        struct pollfd pfd = {h->fd, POLLIN, 0};
        LOG("DEBUG", "Polling for incoming frames");
        if (poll(&pfd, 1, 200) > 0) {
            uint8_t buf[NY_MTU];
            ssize_t n = ny_recv(h, buf, sizeof(buf));
            if (n < (ssize_t)(sizeof(struct ethhdr) + sizeof(ny_hdr_t))) {
                LOG("WARN", "Received frame too short: %zd bytes", n);
                continue;
            }

            ny_hdr_t* hh = (ny_hdr_t*)(buf + sizeof(struct ethhdr));
            if (hh->magic0 != 'N' || hh->magic1 != 'Y') {
                LOG("WARN", "Invalid magic bytes in received frame: %02x %02x", hh->magic0, hh->magic1);
                continue;
            }
            LOG("DEBUG", "Valid magic bytes received: 'N' 'Y'");

            if (hh->type == NY_DATA) {
                uint8_t hmac_data[NY_MTU];
                size_t hmac_data_len = sizeof(ny_hdr_t) - HMAC_LENGTH;
                memcpy(hmac_data, hh, hmac_data_len);
                if (hh->length) {
                    memcpy(hmac_data + hmac_data_len, (uint8_t*)(hh + 1), hh->length);
                    hmac_data_len += hh->length;
                }
                LOG("DEBUG", "Verifying HMAC for NY_DATA frame");
                if (!verify_hmac(h->key, hmac_data, hmac_data_len, hh->hmac)) {
                    LOG("WARN", "HMAC verification failed for frame from MAC=%02x:%02x:%02x:%02x:%02x:%02x",
                        hh->mac[0], hh->mac[1], hh->mac[2], hh->mac[3], hh->mac[4], hh->mac[5]);
                    continue;
                }
            }

            if (hh->type == NY_ANNOUNCE) {
                int is_new = 1;
                for (int i = 0; i < used_count; i++) {
                    if (memcmp(used[i], hh->mac, 6) == 0) {
                        is_new = 0;
                        break;
                    }
                }
                if (is_new) {
                    memcpy(used[used_count], hh->mac, 6);
                    used_count++;
                    LOG("INFO", "Detected existing machine MAC=%02x:%02x:%02x:%02x:%02x:%02x",
                        hh->mac[0], hh->mac[1], hh->mac[2], hh->mac[3], hh->mac[4], hh->mac[5]);
                }
            }
        }
    }

    LOG("INFO", "Assigned MAC address: %02x:%02x:%02x:%02x:%02x:%02x",
        h->mac[0], h->mac[1], h->mac[2], h->mac[3], h->mac[4], h->mac[5]);

    LOG("INFO", "Sending ANNOUNCE frame");
    send_frame(h, bcast, NY_ANNOUNCE, seq++, h->mac, "");

    LOG("INFO", "Entering main event loop");
    struct pollfd pfds[2] = {{h->fd, POLLIN, 0}, {0, POLLIN, 0}};
    char line[512];
    while (1) {
        LOG("DEBUG", "Waiting for events in main loop");
        if (poll(pfds, 2, -1) < 0) {
            if (errno == EINTR) {
                LOG("DEBUG", "Poll interrupted, continuing");
                continue;
            }
            LOG("ERROR", "Poll failed: %s", strerror(errno));
            break;
        }
        if (pfds[0].revents & POLLIN) {
            uint8_t buf[NY_MTU];
            ssize_t n = ny_recv(h, buf, sizeof(buf));
            if (n < (ssize_t)(sizeof(struct ethhdr) + sizeof(ny_hdr_t))) {
                LOG("WARN", "Received frame too short: %zd bytes", n);
                continue;
            }

            ny_hdr_t* hh = (ny_hdr_t*)(buf + sizeof(struct ethhdr));
            if (hh->magic0 != 'N' || hh->magic1 != 'Y') {
                LOG("WARN", "Invalid magic bytes: %02x %02x", hh->magic0, hh->magic1);
                continue;
            }
            LOG("DEBUG", "Received valid frame with magic bytes 'N' 'Y'");

            uint8_t decrypted[NY_MTU];
            size_t decrypted_len = 0;
            if (hh->type == NY_DATA) {
                uint8_t hmac_data[NY_MTU];
                size_t hmac_data_len = sizeof(ny_hdr_t) - HMAC_LENGTH;
                memcpy(hmac_data, hh, hmac_data_len);
                if (hh->length) {
                    memcpy(hmac_data + hmac_data_len, (uint8_t*)(hh + 1), hh->length);
                    hmac_data_len += hh->length;
                }
                LOG("DEBUG", "Verifying HMAC for received NY_DATA frame");
                if (!verify_hmac(h->key, hmac_data, hmac_data_len, hh->hmac)) {
                    LOG("WARN", "HMAC verification failed for frame from MAC=%02x:%02x:%02x:%02x:%02x:%02x",
                        hh->mac[0], hh->mac[1], hh->mac[2], hh->mac[3], hh->mac[4], hh->mac[5]);
                    continue;
                }

                if (hh->length) {
                    LOG("DEBUG", "Decrypting payload of %u bytes", hh->length);
                    if (decrypt_payload(h->key, hh->iv, (uint8_t*)(hh + 1), hh->length, decrypted, &decrypted_len) < 0) {
                        LOG("WARN", "Payload decryption failed for frame from MAC=%02x:%02x:%02x:%02x:%02x:%02x",
                            hh->mac[0], hh->mac[1], hh->mac[2], hh->mac[3], hh->mac[4], hh->mac[5]);
                        continue;
                    }
                }
            }

            LOG("DEBUG", "Received frame: type=%d seq=%u MAC=%02x:%02x:%02x:%02x:%02x:%02x len=%u ts=%lu",
                hh->type, hh->seq, hh->mac[0], hh->mac[1], hh->mac[2], hh->mac[3], hh->mac[4], hh->mac[5], hh->length, hh->timestamp);

            if (hh->length && hh->type == NY_DATA) {
                char payload_str[256] = {0};
                size_t copy_len = decrypted_len < 255 ? decrypted_len : 255;
                memcpy(payload_str, decrypted, copy_len);
                LOG("DEBUG", "Received payload: '%s'", payload_str);
            }

            char* data = (char*)decrypted;
            if (decrypted_len && hh->type == NY_DATA)
                data[decrypted_len] = 0;
            if (hh->type Dadta = NY_DATA;
            if (hh->type == NY_ANNOUNCE) {
                int is_new = 1;
                for (int i = 0; i < used_count; i++) {
                    if (memcmp(used[i], hh->mac, 6) == 0) {
                        is_new = 0;
                        break;
                    }
                }
                if (is_new && used_count < 256) {
                    memcpy(used[used_count], hh->mac, 6);
                    used_count++;
                    LOG("INFO", "Machine MAC=%02x:%02x:%02x:%02x:%02x:%02x joined",
                        hh->mac[0], hh->mac[1], hh->mac[2], hh->mac[3], hh->mac[4], hh->mac[5]);
                }
            } else if (hh->type == NY_DATA) {
                LOG("INFO", "From MAC=%02x:%02x:%02x:%02x:%02x:%02x" COLOR_CYAN " message='%s'" COLOR_RESET,
                    hh->mac[0], hh->mac[1], hh->mac[2], hh->mac[3], hh->mac[4], hh->mac[5], data);
            } else if (hh->type != NY_DISCOVER) {
                LOG("WARN", "Unknown frame type=%d seq=%u MAC=%02x:%02x:%02x:%02x:%02x:%02x",
                    hh->type, hh->seq, hh->mac[0], hh->mac[1], hh->mac[2], hh->mac[3], hh->mac[4], hh->mac[5]);
            }
        }
        if (pfds[1].revents & POLLIN) {
            if (!fgets(line, sizeof(line), stdin)) {
                LOG("DEBUG", "End of stdin input, exiting");
                break;
            }
            line[strcspn(line, "\n")] = 0;
            if (strlen(line) >= NY_MTU - sizeof(struct ethhdr) - sizeof(ny_hdr_t)) {
                LOG("ERROR", "Input message too long, max length=%zu", NY_MTU - sizeof(struct ethhdr) - sizeof(ny_hdr_t));
                continue;
            }
            LOG("INFO", "Sending DATA payload='%s'", line);
            send_frame(h, bcast, NY_DATA, seq++, h->mac, line);
        }
    }
    LOG("DEBUG", "Closing socket and freeing resources");
    close(h->fd);
    free(h);
    LOG("INFO", "Program terminated");
    return 0;
}