/* NY Protocol (PoC)
 *
 * Overview:
 * This source code implements a Proof of Concept (PoC) for the NY protocol, a custom
 * network protocol designed for experimental purposes. It demonstrates raw socket communication
 * over Ethernet using a custom EtherType (0x88B5), with AES-256-CBC encryption and SHA-256 HMAC
 * for secure data transmission. The protocol supports three frame types: DISCOVER, ANNOUNCE,
 * and DATA, facilitating device discovery and secure message exchange.
 *
 * Warning:
 * This is a proof-of-concept implementation and is NOT INTENDED FOR PRODUCTION USE.
 * It uses a hardcoded pre-shared key, which is insecure for real-world applications.
 * For production systems, implement a secure key exchange mechanism and address potential
 * vulnerabilities such as replay attacks, proper error handling, and robust input validation.
 *
 * Dependencies:
 * - Requires OpenSSL for cryptographic operations (AES, HMAC, random IV generation).
 * - Must be run with root privileges to access raw sockets.
 * - Tested on Linux systems with appropriate network interfaces.
 *
 * Limitations:
 * - Hardcoded 256-bit AES key (insecure for production).
 * - Limited error handling and logging for demonstration purposes.
 * - Supports up to 256 unique MAC addresses for device tracking.
 * - No protection against replay attacks or advanced network threats.
 *
 * Author: Kevin Alavik
 * Date: August 2025
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <poll.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <netpacket/packet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <net/if_arp.h>
#include <fcntl.h>
#include <openssl/aes.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#define NY_ETHERTYPE 0x88B5
#define NY_MTU 1500
#define COLOR_GRAY "\033[90m"
#define COLOR_CYAN "\033[36m"
#define COLOR_RESET "\033[0m"
#define LOG(level, fmt, ...) \
    do { \
        time_t t = time(NULL); \
        struct tm *tm = localtime(&t); \
        char ts[32]; \
        strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", tm); \
        printf(COLOR_GRAY "[%s] [%s] " fmt COLOR_RESET "\n", ts, level, ##__VA_ARGS__); \
    } while (0)

#define KEY_LENGTH 32
#define IV_LENGTH 16
#define HMAC_LENGTH 32

static const uint8_t PRE_SHARED_KEY[KEY_LENGTH] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
};

enum { NY_DISCOVER=1, NY_ANNOUNCE=2, NY_DATA=3 };

#pragma pack(push,1)
typedef struct {
    uint8_t  magic0;
    uint8_t  magic1;
    uint8_t  version;
    uint8_t  type;
    uint16_t length;
    uint32_t seq;
    uint8_t  mac[6];
    uint64_t timestamp;
    uint8_t  iv[IV_LENGTH];
    uint8_t  hmac[HMAC_LENGTH];
} ny_hdr_t;
#pragma pack(pop)

typedef struct {
    int fd;
    int ifindex;
    uint8_t mac[6];
    uint8_t key[KEY_LENGTH];
} ny_handle_t;

static void compute_hmac(const uint8_t* key, const uint8_t* data, size_t data_len, uint8_t* hmac) {
    LOG("DEBUG", "Computing HMAC for data of length %zu", data_len);
    HMAC(EVP_sha256(), key, KEY_LENGTH, data, data_len, hmac, NULL);
    LOG("DEBUG", "HMAC computation completed");
}

static int verify_hmac(const uint8_t* key, const uint8_t* data, size_t data_len, const uint8_t* expected_hmac) {
    LOG("DEBUG", "Verifying HMAC for data of length %zu", data_len);
    uint8_t computed_hmac[HMAC_LENGTH];
    compute_hmac(key, data, data_len, computed_hmac);
    int result = memcmp(computed_hmac, expected_hmac, HMAC_LENGTH) == 0;
    LOG("DEBUG", "HMAC verification %s", result ? "succeeded" : "failed");
    return result;
}

static int encrypt_payload(const uint8_t* key, const uint8_t* iv, const uint8_t* in, size_t in_len, uint8_t* out, size_t* out_len) {
    LOG("DEBUG", "Starting payload encryption for %zu bytes", in_len);
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        LOG("ERROR", "Failed to create EVP_CIPHER_CTX for encryption");
        return -1;
    }
    LOG("DEBUG", "EVP_CIPHER_CTX created successfully");

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        LOG("ERROR", "EVP_EncryptInit_ex failed");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    LOG("DEBUG", "Encryption initialized with AES-256-CBC");

    int len, total_len = 0;
    if (EVP_EncryptUpdate(ctx, out, &len, in, in_len) != 1) {
        LOG("ERROR", "EVP_EncryptUpdate failed");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    total_len += len;
    LOG("DEBUG", "Encrypted %d bytes in update step", len);

    if (EVP_EncryptFinal_ex(ctx, out + len, &len) != 1) {
        LOG("ERROR", "EVP_EncryptFinal_ex failed");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    total_len += len;
    LOG("DEBUG", "Finalized encryption, added %d bytes, total %zu bytes", len, total_len);

    EVP_CIPHER_CTX_free(ctx);
    *out_len = total_len;
    LOG("DEBUG", "Encryption completed successfully, output length %zu bytes", *out_len);
    return 0;
}

static int decrypt_payload(const uint8_t* key, const uint8_t* iv, const uint8_t* in, size_t in_len, uint8_t* out, size_t* out_len) {
    LOG("DEBUG", "Starting payload decryption for %zu bytes", in_len);
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        LOG("ERROR", "Failed to create EVP_CIPHER_CTX for decryption");
        return -1;
    }
    LOG("DEBUG", "EVP_CIPHER_CTX created successfully for decryption");

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        LOG("ERROR", "EVP_DecryptInit_ex failed");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    LOG("DEBUG", "Decryption initialized with AES-256-CBC");

    int len, total_len = 0;
    if (EVP_DecryptUpdate(ctx, out, &len, in, in_len) != 1) {
        LOG("ERROR", "EVP_DecryptUpdate failed");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    total_len += len;
    LOG("DEBUG", "Decrypted %d bytes in update step", len);

    if (EVP_DecryptFinal_ex(ctx, out + len, &len) != 1) {
        LOG("ERROR", "EVP_DecryptFinal_ex failed");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    total_len += len;
    LOG("DEBUG", "Finalized decryption, added %d bytes, total %zu bytes", len, total_len);

    EVP_CIPHER_CTX_free(ctx);
    *out_len = total_len;
    LOG("DEBUG", "Decryption completed successfully, output length %zu bytes", *out_len);
    return 0;
}

static int ny_open(ny_handle_t* h, const char* iface) {
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

static ssize_t ny_send(ny_handle_t* h, const uint8_t dst[6], ny_hdr_t* hdr, const uint8_t* payload, size_t payload_len) {
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

static ssize_t ny_recv(ny_handle_t* h, uint8_t* buf, size_t len) {
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

static void send_frame(ny_handle_t* h, const uint8_t dst[6], uint8_t type, uint32_t seq, const uint8_t mac[6], const char* msg) {
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
