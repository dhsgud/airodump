#include <stdio.h>
#include <stdint.h>
#include <pcap.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include "radiotap.h"  // 새로운 헤더 파일 포함

#define MAX_BSSIDS 100

// 802.11 속도 관련 상수
#define RATE_BASIC_FLAG    0x80
#define RATE_MASK         0x7F

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
    int num_mb_rates;
    int mb_rates[16];
    time_t first_seen;
};

struct bssid_info bssids[MAX_BSSIDS];
int bssid_count = 0;

void print_header() {
    printf("%-18s  %4s  %8s  %6s  %3s  %2s  %3s  %-4s %-6s %-4s %s\n",
           "BSSID", "PWR", "Beacons", "#Data", "#/s", "CH", "MB", "ENC", "CIPHER", "AUTH", "ESSID");
    printf("-------------------------------------------------------------------------------\n");
}

void print_bssid_info(struct bssid_info *info) {
    // 최대 속도 찾기
    int max_rate = 0;
    for (int i = 0; i < info->num_mb_rates; i++) {
        if (info->mb_rates[i] > max_rate) {
            max_rate = info->mb_rates[i];
        }
    }

    // 5단위로 반올림
    max_rate = ((max_rate + 2) / 5) * 5;

    printf("%02X:%02X:%02X:%02X:%02X:%02X  %4d  %8d  %6d  %3.0f  %2d  %3d  %-4s %-6s %-4s %s\n",
           info->bssid[0], info->bssid[1], info->bssid[2],
           info->bssid[3], info->bssid[4], info->bssid[5],
           info->power,
           info->beacon_count,
           0,                    // #Data
           info->data_rate,
           info->channel,
           max_rate,            // 5단위로 반올림된 최대 MB 속도
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

void parse_beacon_frame(const unsigned char *frame, struct bssid_info *info) {
    // Capability 필드를 읽어오기 위해 caps를 선언
    uint16_t caps = (frame[34] | (frame[35] << 8));

    const unsigned char *current = frame + 36;  // 비콘 프레임 고정 헤더 이후
    
    // 초기화
    info->num_mb_rates = 0;
    strcpy(info->essid, "<length: 0>");
    info->channel = 0;
    
    // caps 사용
    if (caps & 0x0010) {
        strcpy(info->enc, "WEP");
        strcpy(info->cipher, "WEP");
        strcpy(info->auth, "SKA");
    } else {
        strcpy(info->enc, "OPN");
        strcpy(info->cipher, "");
        strcpy(info->auth, "");
    }

    while (current < frame + 1024) {
        uint8_t tag_num = *current++;
        uint8_t tag_len = *current++;
        
        if (tag_len == 0 || current + tag_len > frame + 1024) {
            break;
        }
        
        switch (tag_num) {
            case 0:  // ESSID
                if (tag_len > 32) tag_len = 32;
                if (tag_len == 0) {
                    strcpy(info->essid, "<length: 0>");
                } else {
                    memset(info->essid, 0, sizeof(info->essid));
                    int printable = 1;
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
                        snprintf(info->essid, sizeof(info->essid), "<length: %d>", tag_len);
                    }
                }
                break;

            case 1:  // Supported Rates
            case 50: // Extended Supported Rates
                for (int i = 0; i < tag_len && info->num_mb_rates < 16; i++) {
                    // 기본 속도 플래그 제거하고 실제 속도값만 추출
                    uint8_t rate = current[i] & 0x7F;
                    
                    // 속도는 0.5Mbps 단위로 인코딩되어 있음
                    float actual_rate = rate * 0.5;
                    
                    // 배열에 저장 (소수점 반올림)
                    info->mb_rates[info->num_mb_rates++] = (int)(actual_rate + 0.5f);
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

            case 45:  // HT Capabilities (802.11n)
                if (tag_len >= 26) {
                    uint16_t ht_caps = current[0] | (current[1] << 8);
                    uint8_t mcs_info[16];
                    memcpy(mcs_info, current + 3, 16);
                    
                    // MCS 비트맵 확인
                    for (int i = 0; i < 8; i++) {  // MCS 0-7 확인
                        if (mcs_info[0] & (1 << i)) {
                            // 20MHz 속도
                            float rate_20 = 6.5f + (i * 6.5f);  // MCS0=6.5, MCS1=13, ...
                            info->mb_rates[info->num_mb_rates++] = (int)(rate_20 + 0.5f);
                            
                            // 40MHz 속도 (지원시)
                            if (ht_caps & 0x0002) {  // 40MHz 지원
                                float rate_40 = rate_20 * 2.1f;  // 약 2.1배 빠름
                                info->mb_rates[info->num_mb_rates++] = (int)(rate_40 + 0.5f);
                            }
                        }
                    }
                    
                    // 듀얼 스트림 (MCS8-15) 확인
                    for (int i = 0; i < 8; i++) {
                        if (mcs_info[1] & (1 << i)) {
                            // 20MHz 듀얼 스트림 속도
                            float rate_20 = (6.5f + (i * 6.5f)) * 2;  // 2 streams
                            info->mb_rates[info->num_mb_rates++] = (int)(rate_20 + 0.5f);
                            
                            // 40MHz 듀얼 스트림 속도 (지원시)
                            if (ht_caps & 0x0002) {
                                float rate_40 = rate_20 * 2.1f;
                                info->mb_rates[info->num_mb_rates++] = (int)(rate_40 + 0.5f);
                            }
                        }
                    }
                }
                break;

            case 191:  // VHT Capabilities (802.11ac)
                if (tag_len >= 12) {
                    uint32_t vht_caps = current[0] | (current[1] << 8) | (current[2] << 16) | (current[3] << 24);
                    uint8_t mcs_map = current[4];
                    
                    // VHT 지원 여부 확인
                    if (vht_caps & 0x0004) {  // 80MHz 지원
                        // 기본 VHT 속도들
                        info->mb_rates[info->num_mb_rates++] = 292;  // VHT 1SS
                        info->mb_rates[info->num_mb_rates++] = 433;  // VHT 1SS MCS9
                        
                        // 듀얼 스트림 지원시
                        if ((mcs_map & 0x0C) != 0x0C) {  // 두 번째 스트림 지원
                            info->mb_rates[info->num_mb_rates++] = 585;  // VHT 2SS
                            info->mb_rates[info->num_mb_rates++] = 866;  // VHT 2SS MCS9
                        }
                    }
                    
                    // 160MHz 지원시
                    if (vht_caps & 0x0008) {
                        info->mb_rates[info->num_mb_rates++] = 866;   // VHT 1SS 160MHz
                        info->mb_rates[info->num_mb_rates++] = 1733;  // VHT 2SS 160MHz
                    }
                }
                break;
        }
        current += tag_len;
    }

    info->first_seen = time(NULL);
}

void packet_handler(unsigned char *user, const struct pcap_pkthdr *pkthdr, const unsigned char *packet) {
    struct radiotap_header *rtap_hdr = (struct radiotap_header *)packet;
    const unsigned char *frame = packet + rtap_hdr->len;
    
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
