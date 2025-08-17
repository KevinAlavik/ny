#ifndef NY_PROTOCOL_H
#define NY_PROTOCOL_H

#include <stdint.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <sys/socket.h>

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

int ny_open(ny_handle_t* h, const char* iface);
ssize_t ny_send(ny_handle_t* h, const uint8_t dst[6], ny_hdr_t* hdr, const uint8_t* payload, size_t payload_len);
ssize_t ny_recv(ny_handle_t* h, uint8_t* buf, size_t len);
void send_frame(ny_handle_t* h, const uint8_t dst[6], uint8_t type, uint32_t seq, const uint8_t mac[6], const char* msg);

#endif /* NY_PROTOCOL_H */