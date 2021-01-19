#include <cstdio>
#include <pcap.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <map>
#include "protocol-hdr.h"

void usage();

struct Stat {
	uint32_t tx_packets;
	uint32_t tx_bytes;
	uint32_t rx_packets;
	uint32_t rx_bytes;
};

int main(int argc, char* argv[]) {
	// check syntax
	if (argc != 2) {
		usage();
		return -1;
	}

	//// declare arguments
	char* pcap_filename = argv[1];
	
	// open my network interface
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_offline(pcap_filename, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "Error: could not open file %s. (%s)\n",
		        pcap_filename, errbuf);
		return -1;
	}
	
	// maps for statistics
	std::map<uint32_t, Stat> stat_endpoint_ip;
	
	/* file reading on loop */
	while (true) {
		/** variables
		 * header: packet header
		 * packet: packet content
		 * res: result code of pcap reading
		 */
		struct pcap_pkthdr* header;
		const uint8_t* packet;
		int res = pcap_next_ex(handle, &header, &packet);

		if (res == 0) continue;        // not captured
		if (res == -1 || res == -2) {  // quit
			// printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			break;
		}

		// printf(" ** %u bytes read ** \n", header->caplen);

		/* adjust the packet with Ethernet protocol */
		Ethernet *ethernet = (Ethernet*) packet;

		/* check if EtherType is IPv4 or not */
		if (ntohs(ethernet->eth_type) != ETH_TYPE_IPv4) {
			// printf("This packet is not IPv4.\n");
			continue;
		}

		/* adjust the packet with IPv4 protocol */
		IPv4 *ipv4 = (IPv4*) (packet + ETH_HEADER_LEN);

		/* apply to statistics */
		uint32_t src_ip = (ipv4->src_ip_addr).ip;
		uint32_t dst_ip = (ipv4->dst_ip_addr).ip;

		std::map<uint32_t, Stat>::iterator stat_finder = stat_endpoint_ip.find(src_ip);
		std::pair<std::map<uint32_t, Stat>::iterator, bool> insert_info;

		if (stat_finder == stat_endpoint_ip.end()) {
			insert_info = stat_endpoint_ip.insert({src_ip, Stat()});
			stat_finder = insert_info.first;
		}

		stat_finder->second.tx_packets += 1;
		stat_finder->second.tx_bytes += header->caplen;
		
		stat_finder = stat_endpoint_ip.find(dst_ip);

		if (stat_finder == stat_endpoint_ip.end()) {
			insert_info = stat_endpoint_ip.insert({dst_ip, Stat()});
			stat_finder = insert_info.first;
		}

		stat_finder->second.rx_packets += 1;
		stat_finder->second.rx_bytes += header->caplen;
	}
	
	for (auto &map_elem : stat_endpoint_ip) {
		IPv4Addr addr;
		addr.ip = map_elem.first;
		addr.print_ipv4_addr();
		printf(": Tx Packets=%u, Tx Bytes=%u, Rx Packets=%u, Rx Bytes=%u\n",
		       stat_endpoint_ip[map_elem.first].tx_packets,
		       stat_endpoint_ip[map_elem.first].tx_bytes,
		       stat_endpoint_ip[map_elem.first].rx_packets,
		       stat_endpoint_ip[map_elem.first].rx_bytes
		);
	}

	//// close pcap
	pcap_close(handle);
}



void usage() {
	printf("syntax: packet-stat <pcap file>\n");
	printf("sample: packet-stat test.pcap\n");
}

