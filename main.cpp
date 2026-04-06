#include <iostream>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <map>
#include <vector>
#include <string>
#include <iomanip>

// Simple Terminal Visuals (Colors)
#define RESET   "\033[0m"
#define RED     "\033[31m"
#define GREEN   "\033[32m"
#define YELLOW  "\033[33m"
#define CYAN    "\033[36m"
#define BOLD    "\033[1m"

// Configuration
const int SYN_THRESHOLD = 20; // Alerts after 20 SYNs from one IP

struct Stats {
    int syn_count = 0;
};

std::map<std::string, Stats> ip_tracker;

void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    struct ip *ip_header = (struct ip *)(packet + 14); // Skip Ethernet header (14 bytes)
    
    // Check if it's a TCP packet
    if (ip_header->ip_p == IPPROTO_TCP) {
        int ip_header_len = ip_header->ip_hl * 4;
        struct tcphdr *tcp_header = (struct tcphdr *)(packet + 14 + ip_header_len);
        
        // Extract Source IP
        std::string src_ip = inet_ntoa(ip_header->ip_src);
        
        // Check for SYN flag (and not ACK)
        if ((tcp_header->th_flags & TH_SYN) && !(tcp_header->th_flags & TH_ACK)) {
            ip_tracker[src_ip].syn_count++;

            // LIVE LOGS
            std::cout << CYAN << "[INFO] " << RESET << "SYN from " << src_ip 
                      << " | Count: " << ip_tracker[src_ip].syn_count << std::endl;

            // DETECTION LOGIC
            if (ip_tracker[src_ip].syn_count > SYN_THRESHOLD) {
                std::cout << RED << BOLD << "!!! ALERT: SYN FLOOD DETECTED FROM " << src_ip << " !!!" << RESET << std::endl;
            }
        }
    }
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        std::cout << "Usage: sudo ./sentinel <interface_name>" << std::endl;
        std::cout << "Hint: Use 'ifconfig' to find your interface (usually en0)" << std::endl;
        return 1;
    }

    char *dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    std::cout << BOLD << GREEN << "--- SentinelSYN: Live Network Monitor Starting ---" << RESET << std::endl;
    std::cout << "Monitoring interface: " << YELLOW << dev << RESET << std::endl;

    // Open interface for live sniffing
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        std::cerr << "Couldn't open device " << dev << ": " << errbuf << std::endl;
        return 2;
    }

    // Start sniffing loop
    pcap_loop(handle, 0, packet_handler, NULL);

    pcap_close(handle);
    return 0;
}