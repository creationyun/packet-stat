#include <cstdio>
#include <pcap.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <map>
#include "protocol-hdr.h"

void usage();

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
	std::map<uint32_t, uint32_t> stat_endpoint_ip_tx_packets;
	std::map<uint32_t, uint32_t> stat_endpoint_ip_tx_bytes;
	std::map<uint32_t, uint32_t> stat_endpoint_ip_rx_packets;
	std::map<uint32_t, uint32_t> stat_endpoint_ip_rx_bytes;
	
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
		
		if (stat_endpoint_ip_tx_packets.find(src_ip) != stat_endpoint_ip_tx_packets.end()) {
			stat_endpoint_ip_tx_packets[src_ip] += 1;
			stat_endpoint_ip_tx_bytes[src_ip] += header->caplen;
		} else {
			stat_endpoint_ip_tx_packets[src_ip] = 1;
			stat_endpoint_ip_tx_bytes[src_ip] = header->caplen;
		}
		
		if (stat_endpoint_ip_rx_packets.find(dst_ip) != stat_endpoint_ip_rx_packets.end()) {
			stat_endpoint_ip_rx_packets[dst_ip] += 1;
			stat_endpoint_ip_rx_bytes[dst_ip] += header->caplen;
		} else {
			stat_endpoint_ip_rx_packets[dst_ip] = 1;
			stat_endpoint_ip_rx_bytes[dst_ip] = header->caplen;
		}
		
		if (stat_endpoint_ip_tx_packets.find(dst_ip) == stat_endpoint_ip_tx_packets.end()) {
			stat_endpoint_ip_tx_packets[dst_ip] = 0;
			stat_endpoint_ip_tx_bytes[dst_ip] = 0;
		}
		
		if (stat_endpoint_ip_rx_packets.find(src_ip) == stat_endpoint_ip_rx_packets.end()) {
			stat_endpoint_ip_rx_packets[src_ip] = 0;
			stat_endpoint_ip_rx_bytes[src_ip] = 0;
		}
	}
	
	for (auto &map_elem : stat_endpoint_ip_tx_packets) {
		IPv4Addr addr;
		addr.ip = map_elem.first;
		addr.print_ipv4_addr();
		printf(": Tx Packets=%u, Tx Bytes=%u, Rx Packets=%u, Rx Bytes=%u\n",
		       stat_endpoint_ip_tx_packets[map_elem.first],
		       stat_endpoint_ip_tx_bytes[map_elem.first],
		       stat_endpoint_ip_rx_packets[map_elem.first],
		       stat_endpoint_ip_rx_bytes[map_elem.first]
		);
	}

	//// close pcap
	pcap_close(handle);
}



void usage() {
	printf("syntax: packet-stat <pcap file>\n");
	printf("sample: packet-stat test.pcap\n");
}

