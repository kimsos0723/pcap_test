#include <arpa/inet.h>
#include <cstdint>
#include <cstdio>
#include <iostream>
#include <pcap/pcap.h>
#include <vector>

using HWAddr = uint8_t[6];
using IPAddr = uint8_t[4];

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
	void print_ip(IPAddr ip) 
	{
		char ip_str[20];
		inet_ntop(AF_INET, &(ip), ip_str, sizeof(ip_str));
		printf("%s\n",ip_str);
	}
    void show()
    {        
        printf("\tsrc: ");
		print_ip(src);
        printf("\tdst: ");
		print_ip(dst);
    }
};

class Ethernet {
public:
    HWAddr dst;
    HWAddr src;
    uint16_t type;

public:
	void print_mac(HWAddr mac) 
	{
		printf("%02x:%02x:%02x:%02x:%02x:%02x\n", mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
	}
    void show()
    {
        printf("\tdst: ");
		print_mac(dst);
        printf("\tsrc: ");
		print_mac(src);
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

	void print_port(uint16_t port) 
	{
		printf("%d\n", ntohs(port));
	}
    void show()
    {
        printf("\tsrc: ");
		print_port(this->sport);
        printf("\tdst: ");
		print_port(this->dport);
    }
};

void print_tcp_data(int tol, int hl, const uint8_t* packet)
{
    int diff = tol - hl;
    diff = diff >= 10 ? 10 : diff;
    printf("\tTCP data: ");
    for (int i = 0; i < diff; i++) {
        printf("%02x ", packet[hl + i]);
    }
}

int main(int argc, char const* argv[])
{
    if (argc != 2) {
        fprintf(stderr, "please input network device name by parameter\n");
        return -1;
    }
    pcap_pkthdr* header;
    const uint8_t* frame;
    char err_buf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = nullptr;
    int res = 0;
    char* device_name = (char*)argv[1];
    handle = pcap_open_live(device_name, 1024, 0, 512, err_buf);
    if (handle == NULL) {
        fprintf(stderr, "couldn't open device %s: %s\n", device_name, err_buf);
        return -1;
    }

    while ((res = pcap_next_ex(handle, &header, &frame)) >= 0) {
        if (res == 0)
            continue;
        Ethernet* eth = (Ethernet*)frame;
        if (ntohs(eth->type) == 0x0800) {
            IP* ip = (IP*)(frame + sizeof(Ethernet));
            if (ip->protocol == 0x06) {
                TCP* tcp = (TCP*)(frame + sizeof(Ethernet) + sizeof(IP));
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