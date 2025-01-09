#include <stdio.h>
#include <stdint.h>
#include <pcap.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#define MAX_BSSIDS 100

struct bssid_info {
    uint8_t bssid[6];
    int beacon_count;
    int8_t power;
    int is_active;
    time_t last_seen;
    float data_rate;
    uint8_t channel;
    int mb_rate;
    char enc[10];
    char cipher[10];
    char auth[10];
    char essid[33];
};

struct bssid_info bssids[MAX_BSSIDS];
int bssid_count = 0;

// Radiotap 헤더 구조체
struct radiotap_header {
    uint8_t version;
    uint8_t pad;
    uint16_t len;
    uint32_t present;
} __attribute__((__packed__));

void print_header() {
    printf("BSSID              PWR  Beacons    #Data  #/s  CH  MB   ENC  CIPHER AUTH ESSID\n");
    printf("-------------------------------------------------------------------------------\n");
}

void print_bssid_info(struct bssid_info *info) {
    printf("%02X:%02X:%02X:%02X:%02X:%02X  %3d  %7d  %6d  %3.0f  %2d  %3d  %-4s %-6s %-4s %s\n",
           info->bssid[0], info->bssid[1], info->bssid[2],
           info->bssid[3], info->bssid[4], info->bssid[5],
           info->power,
           info->beacon_count,
           0,
           info->data_rate,
           info->channel,
           info->mb_rate,
           info->enc,
           info->cipher,
           info->auth,
           info->essid);
}

int find_bssid(uint8_t *bssid) {
    for (int i = 0; i < bssid_count; i++) {
        if (memcmp(bssids[i].bssid, bssid, 6) == 0) {
            return i;
        }
    }
    return -1;
}

void parse_beacon_frame(const u_char *frame, struct bssid_info *info) {
    const u_char *current = frame + 36;
    uint16_t caps = *(uint16_t *)(frame + 34);
    
    // 기본값 설정
    strcpy(info->essid, "<length: 0>");  // ESSID가 없을 경우 기본값
    info->channel = 0;
    
    if (caps & 0x0010) {
        strcpy(info->enc, "WEP");
        strcpy(info->cipher, "WEP");
        strcpy(info->auth, "SKA");
    } else {
        strcpy(info->enc, "");
        strcpy(info->cipher, "");
        strcpy(info->auth, "");
    }

    while (current < frame + 1024) {
        uint8_t tag_num = *current++;
        uint8_t tag_len = *current++;
        
        if (tag_len == 0 || current + tag_len > frame + 1024) {
            break;  // 잘못된 길이 체크
        }
        
        switch (tag_num) {
            case 0:  // ESSID
                if (tag_len > 32) tag_len = 32;
                if (tag_len == 0) {
                    strcpy(info->essid, "<length: 0>");
                } else {
                    memset(info->essid, 0, sizeof(info->essid));
                    int printable = 1;
                    // 출력 가능한 문자인지 확인
                    for (int i = 0; i < tag_len; i++) {
                        if (current[i] < 32 || current[i] > 126) {
                            printable = 0;
                            break;
                        }
                    }
                    if (printable) {
                        memcpy(info->essid, current, tag_len);
                        info->essid[tag_len] = '\0';
                    } else {
                        strcpy(info->essid, "<hidden>");
                    }
                }
                break;
                
            case 3:  // Channel
                info->channel = *current;
                break;
                
            case 48:  // RSN (WPA2)
                strcpy(info->enc, "WPA2");
                strcpy(info->cipher, "CCMP");
                strcpy(info->auth, "PSK");
                break;
                
            case 221:  // Vendor Specific (WPA1)
                if (tag_len >= 4 && memcmp(current, "\x00\x50\xf2\x01", 4) == 0) {
                    strcpy(info->enc, "WPA");
                    strcpy(info->cipher, "TKIP");
                    strcpy(info->auth, "PSK");
                }
                break;
        }
        current += tag_len;
    }
}

void packet_handler(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    struct radiotap_header *rtap_hdr = (struct radiotap_header *)packet;
    const u_char *frame = packet + rtap_hdr->len;
    
    if ((frame[0] & 0xFC) != 0x80) {
        return;
    }

    int8_t signal_power = 0;
    if (rtap_hdr->len >= 22) {
        signal_power = (int8_t)packet[22];
    }

    uint8_t bssid[6];
    memcpy(bssid, frame + 10, 6);
    
    int idx = find_bssid(bssid);
    if (idx == -1) {
        if (bssid_count < MAX_BSSIDS) {
            memcpy(bssids[bssid_count].bssid, bssid, 6);
            bssids[bssid_count].beacon_count = 1;
            bssids[bssid_count].power = signal_power;
            bssids[bssid_count].is_active = 1;
            bssids[bssid_count].last_seen = time(NULL);
            bssids[bssid_count].data_rate = 0;
            bssids[bssid_count].mb_rate = 54;
            
            parse_beacon_frame(frame, &bssids[bssid_count]);
            
            bssid_count++;
        }
    } else {
        bssids[idx].beacon_count++;
        bssids[idx].last_seen = time(NULL);
        if (signal_power > bssids[idx].power) {
            bssids[idx].power = signal_power;
        }
        bssids[idx].data_rate = (bssids[idx].data_rate * 0.7) + 
                               (((float)bssids[idx].beacon_count / 
                                 (time(NULL) - bssids[idx].last_seen)) * 0.3);
    }

    time_t current_time = time(NULL);
    for (int i = 0; i < bssid_count; i++) {
        if (current_time - bssids[i].last_seen > 10) {
            bssids[i].is_active = 0;
        }
    }

    system("clear");
    print_header();
    for (int i = 0; i < bssid_count; i++) {
        if (bssids[i].is_active) {
            print_bssid_info(&bssids[i]);
        }
    }
}

int main(int argc, char *argv[]) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    
    if (argc != 2) {
        printf("사용법: %s <인터페이스>\n", argv[0]);
        return 1;
    }

    handle = pcap_open_live(argv[1], BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "인터페이스를 열 수 없습니다: %s\n", errbuf);
        return 2;
    }

    printf("%s 인터페이스에서 BSSID 캡처 시작...\n", argv[1]);
    print_header();
    pcap_loop(handle, 0, packet_handler, NULL);

    pcap_close(handle);
    return 0;
}
