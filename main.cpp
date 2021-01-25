#include <cstdio>
#include <pcap.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <map>
#include "protocol-hdr.h"

void usage();

struct Stat {
	uint32_t packets{0};
	uint32_t bytes{0};
};

struct EndpointStat {
	Stat tx, rx;
};

struct ConvStat {
	Stat first_to_second, second_to_first;
};

typedef std::pair<uint32_t, uint16_t> IpAndPort;

typedef std::map<uint32_t, EndpointStat> IpStat;
typedef std::map<MacAddr, EndpointStat> MacStat;
typedef std::map<IpAndPort, EndpointStat> TcpUdpStat;

typedef std::map<std::pair<uint32_t, uint32_t>, Stat> IpFlowStat;
typedef std::map<std::pair<uint32_t, uint32_t>, ConvStat> IpConvStat;

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
	IpFlowStat stat_flow_ip;
	
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
				insert_info = stat_endpoint_mac.insert({src_mac, EndpointStat()});
				stat_finder = insert_info.first;
			}

			stat_finder->second.tx.packets += 1;
			stat_finder->second.tx.bytes += header->caplen;

			stat_finder = stat_endpoint_mac.find(dst_mac);

			if (stat_finder == stat_endpoint_mac.end()) {
				insert_info = stat_endpoint_mac.insert({dst_mac, EndpointStat()});
				stat_finder = insert_info.first;
			}

			stat_finder->second.rx.packets += 1;
			stat_finder->second.rx.bytes += header->caplen;
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
				insert_info = stat_endpoint_ip.insert({src_ip, EndpointStat()});
				stat_finder = insert_info.first;
			}

			stat_finder->second.tx.packets += 1;
			stat_finder->second.tx.bytes += header->caplen;
			
			stat_finder = stat_endpoint_ip.find(dst_ip);

			if (stat_finder == stat_endpoint_ip.end()) {
				insert_info = stat_endpoint_ip.insert({dst_ip, EndpointStat()});
				stat_finder = insert_info.first;
			}

			stat_finder->second.rx.packets += 1;
			stat_finder->second.rx.bytes += header->caplen;

			// IPv4 flow statistics
			IpFlowStat::iterator flowstat_finder = stat_flow_ip.find({src_ip, dst_ip});
			std::pair<IpFlowStat::iterator, bool> flow_insert_info;

			if (flowstat_finder == stat_flow_ip.end()) {
				flow_insert_info = stat_flow_ip.insert({{src_ip, dst_ip}, Stat()});
				flowstat_finder = flow_insert_info.first;
			}

			flowstat_finder->second.packets += 1;
			flowstat_finder->second.bytes += header->caplen;
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
				insert_info = target_stat_endpoint->insert({{src_ip, src_port}, EndpointStat()});
				stat_finder = insert_info.first;
			}

			stat_finder->second.tx.packets += 1;
			stat_finder->second.tx.bytes += header->caplen;
			
			stat_finder = target_stat_endpoint->find({dst_ip, dst_port});

			if (stat_finder == target_stat_endpoint->end()) {
				insert_info = target_stat_endpoint->insert({{dst_ip, dst_port}, EndpointStat()});
				stat_finder = insert_info.first;
			}

			stat_finder->second.rx.packets += 1;
			stat_finder->second.rx.bytes += header->caplen;

			break;
		} while (true);
	}

	//// close pcap
	pcap_close(handle);

	printf("Statistics of Endpoint by MAC Address\n");

	for (auto &map_elem : stat_endpoint_mac) {
		MacAddr addr = map_elem.first;
		EndpointStat& stat = map_elem.second;
		addr.print_mac_addr();
		printf(": Tx Packets=%u, Tx Bytes=%u, Rx Packets=%u, Rx Bytes=%u\n",
		       stat.tx.packets,
		       stat.tx.bytes,
		       stat.rx.packets,
		       stat.rx.bytes
		);
	}

	printf("\n");
	printf("Statistics of Endpoint by IPv4 Address\n");
	
	for (auto &map_elem : stat_endpoint_ip) {
		IPv4Addr addr;
		EndpointStat& stat = map_elem.second;
		addr.ip = map_elem.first;
		addr.print_ipv4_addr();
		printf(": Tx Packets=%u, Tx Bytes=%u, Rx Packets=%u, Rx Bytes=%u\n",
		       stat.tx.packets,
		       stat.tx.bytes,
		       stat.rx.packets,
		       stat.rx.bytes
		);
	}

	printf("\n");
	printf("Statistics of Endpoint by TCP\n");
	
	for (auto &map_elem : stat_endpoint_tcp) {
		IPv4Addr addr;
		EndpointStat& stat = map_elem.second;
		addr.ip = map_elem.first.first;
		addr.print_ipv4_addr();
		printf(":%d: Tx Packets=%u, Tx Bytes=%u, Rx Packets=%u, Rx Bytes=%u\n",
		       ntohs(map_elem.first.second),
		       stat.tx.packets,
		       stat.tx.bytes,
		       stat.rx.packets,
		       stat.rx.bytes
		);
	}

	printf("\n");
	printf("Statistics of Endpoint by UDP\n");
	
	for (auto &map_elem : stat_endpoint_udp) {
		IPv4Addr addr;
		EndpointStat& stat = map_elem.second;
		addr.ip = map_elem.first.first;
		addr.print_ipv4_addr();
		printf(":%d: Tx Packets=%u, Tx Bytes=%u, Rx Packets=%u, Rx Bytes=%u\n",
		       ntohs(map_elem.first.second),
		       stat.tx.packets,
		       stat.tx.bytes,
		       stat.rx.packets,
		       stat.rx.bytes
		);
	}

	printf("\n");
	printf("Statistics of Conversation by IPv4\n");

	IpConvStat stat_conv_ip;
	
	for (auto &map_elem : stat_flow_ip) {
		std::pair<uint32_t, uint32_t> ip_pair = map_elem.first, ip_reverse_pair;
		Stat &conv = map_elem.second;
		ip_reverse_pair = {ip_pair.second, ip_pair.first};

		IpConvStat::iterator it1 = stat_conv_ip.find(ip_pair);
		IpConvStat::iterator it2 = stat_conv_ip.find(ip_reverse_pair);

		if (it1 == stat_conv_ip.end()) {
			if (it2 == stat_conv_ip.end()) {
				stat_conv_ip.insert({ip_pair, {conv, Stat()}});
			}
			else {
				it2->second.second_to_first = conv;
			}
		}
	}

	for (auto &map_elem : stat_conv_ip) {
		IPv4Addr addr_first, addr_second;
		ConvStat& stat = map_elem.second;
		addr_first.ip = map_elem.first.first;
		addr_second.ip = map_elem.first.second;
		addr_first.print_ipv4_addr();
		printf(" - ");
		addr_second.print_ipv4_addr();
		printf(": 1->2 Packets=%u, 1->2 Bytes=%u, 2->1 Packets=%u, 2->1 Bytes=%u\n",
		       stat.first_to_second.packets,
		       stat.first_to_second.bytes,
		       stat.second_to_first.packets,
		       stat.second_to_first.bytes
		);
	}
}



void usage() {
	printf("syntax: packet-stat <pcap file>\n");
	printf("sample: packet-stat test.pcap\n");
}

