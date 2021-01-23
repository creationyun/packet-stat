#include <cstdio>
#include <pcap.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <map>
#include "protocol-hdr.h"

void usage();

struct Stat {
	uint32_t tx_packets{0};
	uint32_t tx_bytes{0};
	uint32_t rx_packets{0};
	uint32_t rx_bytes{0};
};

typedef std::map<uint32_t, Stat> IpStat;
typedef std::map<MacAddr, Stat> MacStat;
typedef std::map<std::pair<uint32_t, uint16_t>, Stat> TcpUdpStat;

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
	IpStat stat_endpoint_ip;
	MacStat stat_endpoint_mac;
	TcpUdpStat stat_endpoint_tcp, stat_endpoint_udp;
	
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

		/* apply to MAC statistics */
		{
			MacAddr src_mac = ethernet->src_mac_addr;
			MacAddr dst_mac = ethernet->dst_mac_addr;

			MacStat::iterator stat_finder = stat_endpoint_mac.find(src_mac);
			std::pair<MacStat::iterator, bool> insert_info;

			if (stat_finder == stat_endpoint_mac.end()) {
				insert_info = stat_endpoint_mac.insert({src_mac, Stat()});
				stat_finder = insert_info.first;
			}

			stat_finder->second.tx_packets += 1;
			stat_finder->second.tx_bytes += header->caplen;

			stat_finder = stat_endpoint_mac.find(dst_mac);

			if (stat_finder == stat_endpoint_mac.end()) {
				insert_info = stat_endpoint_mac.insert({dst_mac, Stat()});
				stat_finder = insert_info.first;
			}

			stat_finder->second.rx_packets += 1;
			stat_finder->second.rx_bytes += header->caplen;
		}

		/* adjust the packet with IPv4 protocol */
		IPv4 *ipv4 = (IPv4*) (packet + ETH_HEADER_LEN);

		/* apply to IPv4 statistics */
		{
			uint32_t src_ip = (ipv4->src_ip_addr).ip;
			uint32_t dst_ip = (ipv4->dst_ip_addr).ip;

			IpStat::iterator stat_finder = stat_endpoint_ip.find(src_ip);
			std::pair<IpStat::iterator, bool> insert_info;

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

		/* apply to TCP or UDP statistics */
		do {
			uint32_t src_ip = (ipv4->src_ip_addr).ip;
			uint32_t dst_ip = (ipv4->dst_ip_addr).ip;
			uint16_t src_port, dst_port;
			TcpUdpStat* target_stat_endpoint;

			/* adjust the packet with TCP or UDP protocol */
			if (ipv4->proto == IP_PROTO_TCP) {
				TCP *tcp = (TCP*) (packet + ETH_HEADER_LEN + ipv4->get_ip_hdrlen());
				src_port = tcp->src_port;
				dst_port = tcp->dst_port;
				target_stat_endpoint = &stat_endpoint_tcp;
			}
			else if (ipv4->proto == IP_PROTO_UDP) {
				UDP *udp = (UDP*) (packet + ETH_HEADER_LEN + ipv4->get_ip_hdrlen());
				src_port = udp->src_port;
				dst_port = udp->dst_port;
				target_stat_endpoint = &stat_endpoint_udp;
			}
			else {
				break;
			}

			TcpUdpStat::iterator stat_finder = target_stat_endpoint->find({src_ip, src_port});
			std::pair<TcpUdpStat::iterator, bool> insert_info;

			if (stat_finder == target_stat_endpoint->end()) {
				insert_info = target_stat_endpoint->insert({{src_ip, src_port}, Stat()});
				stat_finder = insert_info.first;
			}

			stat_finder->second.tx_packets += 1;
			stat_finder->second.tx_bytes += header->caplen;
			
			stat_finder = target_stat_endpoint->find({dst_ip, dst_port});

			if (stat_finder == target_stat_endpoint->end()) {
				insert_info = target_stat_endpoint->insert({{dst_ip, dst_port}, Stat()});
				stat_finder = insert_info.first;
			}

			stat_finder->second.rx_packets += 1;
			stat_finder->second.rx_bytes += header->caplen;

			break;
		} while (true);
	}

	for (auto &map_elem : stat_endpoint_mac) {
		MacAddr addr = map_elem.first;
		Stat& stat = map_elem.second;
		addr.print_mac_addr();
		printf(": Tx Packets=%u, Tx Bytes=%u, Rx Packets=%u, Rx Bytes=%u\n",
		       stat.tx_packets,
		       stat.tx_bytes,
		       stat.rx_packets,
		       stat.rx_bytes
		);
	}

	printf("\n");
	
	for (auto &map_elem : stat_endpoint_ip) {
		IPv4Addr addr;
		Stat& stat = map_elem.second;
		addr.ip = map_elem.first;
		addr.print_ipv4_addr();
		printf(": Tx Packets=%u, Tx Bytes=%u, Rx Packets=%u, Rx Bytes=%u\n",
		       stat.tx_packets,
		       stat.tx_bytes,
		       stat.rx_packets,
		       stat.rx_bytes
		);
	}

	printf("\n");
	
	for (auto &map_elem : stat_endpoint_tcp) {
		IPv4Addr addr;
		Stat& stat = map_elem.second;
		addr.ip = map_elem.first.first;
		addr.print_ipv4_addr();
		printf(":%d: Tx Packets=%u, Tx Bytes=%u, Rx Packets=%u, Rx Bytes=%u\n",
		       ntohs(map_elem.first.second),
		       stat.tx_packets,
		       stat.tx_bytes,
		       stat.rx_packets,
		       stat.rx_bytes
		);
	}

	printf("\n");
	
	for (auto &map_elem : stat_endpoint_udp) {
		IPv4Addr addr;
		Stat& stat = map_elem.second;
		addr.ip = map_elem.first.first;
		addr.print_ipv4_addr();
		printf(":%d: Tx Packets=%u, Tx Bytes=%u, Rx Packets=%u, Rx Bytes=%u\n",
		       ntohs(map_elem.first.second),
		       stat.tx_packets,
		       stat.tx_bytes,
		       stat.rx_packets,
		       stat.rx_bytes
		);
	}

	//// close pcap
	pcap_close(handle);
}



void usage() {
	printf("syntax: packet-stat <pcap file>\n");
	printf("sample: packet-stat test.pcap\n");
}

