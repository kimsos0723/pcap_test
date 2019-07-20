#include <arpa/inet.h>
#include <pcap/pcap.h>
#include <cstdint>
#include <cstdio>
#include <iostream>
#include <vector>

using HWAddr = uint8_t[6];
using IPAddr = uint8_t[4];

using InerPDU = std::vector<uint8_t>;

class IP {
 public:
  uint8_t vhl;
  uint8_t tos;
  uint16_t tol;
  uint16_t id;
  uint16_t flags;
  uint8_t ttl;
  uint8_t protocol;
  uint16_t h_checksum;
  IPAddr src;
  IPAddr dst;

 public:
  void show() {
    char ip_str[20];
    inet_ntop(AF_INET, &(src), ip_str, sizeof(ip_str));
    printf("\tsrc: %s\n", ip_str);
    inet_ntop(AF_INET, &(dst), ip_str, sizeof(ip_str));
    printf("\tdst: %s\n", ip_str);
  }
};

class Ethernet {
 public:
  HWAddr dst;
  HWAddr src;
  uint16_t type;

 public:
  void show() {
    printf("\tdst: %02x:%02x:%02x:%02x:%02x:%02x\n", dst[0], dst[1], dst[2],
           dst[3], dst[4], dst[5]);
    printf("\tsrc: %02x:%02x:%02x:%02x:%02x:%02x\n", src[0], src[1], src[2],
           src[3], src[4], src[5]);
    // printf("type: %d\n", type);
  }
};

class TCP {
 public:
  uint16_t sport;
  uint16_t dport;
  uint32_t sq_num;
  uint32_t ackno_num;
  uint16_t flags;
  uint16_t winow_size;
  uint16_t checksum;
  uint16_t urg_pointer;
  void show() {
    printf("\tsrc port: %d\n", ntohs(this->sport));
    printf("\tdst port: %d\n", ntohs(this->dport));
  }
};

void print_tcp_data(int tol, int hl, const uint8_t *packet) {
  int diff = tol - hl;
  diff = diff > 10 ? 10 : diff;
  printf("\tTCP data: ");
  for (int i = 0; i < diff; i++) {
    printf("%02x ", packet[hl + i]);
  }
}


int main(int argc, char const *argv[])
{
  if(argc != 2 ) {
    fprintf(stderr, "please input network device name by parameter\n");
    return -1;
  }
  pcap_pkthdr *header;
  const uint8_t *frame;
  char err_buf[PCAP_ERRBUF_SIZE];
  pcap_t *handle = nullptr;
  int res = 0;
  char* device_name = (char*)argv[1];
  handle = pcap_open_live(device_name, 1024, 0, 512, err_buf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", device_name, err_buf);
    return -1;
  }

  while ((res = pcap_next_ex(handle, &header, &frame)) >= 0) {
    if (res == 0) continue;
    Ethernet *eth = (Ethernet *)frame;
    if (ntohs(eth->type) == 0x0800) {
      IP *ip = (IP *)(frame + sizeof(Ethernet));      
      if (ip->protocol == 0x06) {
        TCP *tcp = (TCP *)(frame + sizeof(Ethernet) + sizeof(IP));
        int hl = 14 + ((ip->vhl & 0x0f) + ((tcp->flags & 0xf0) >> 4)) * 4;
        printf("Ethernet \n");
        eth->show();
        printf("IP \n");
        ip->show();
        printf("TCP \n");
        tcp->show();
        print_tcp_data(header->caplen, hl, frame);
      }
      printf("\n");
    }
  }

  return 0;
}