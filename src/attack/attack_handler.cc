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

	watch_list_name_ = "what_list";

	OptionParser options;
	options.parse(argc, argv, long_options);

	if(options.present(white_list)) {
		watch_list_name_ = string(options.argument(white_list));
	}

	DEBUG("White list name set to: " << watch_list_name_);
}

void Attack_Handler::postrouting(IPPacket & p){
	DEBUG("Received packet");

	if (p.get_ip_protocol() != TCP) {
		DEBUG("Accepting non TCP Packet (" << (int)p.get_ip_protocol() << ")");
		p.accept();
		return;
	}

	TCPPacket packet(p, false);
	if(on_watch_list(packet)){
		DEBUG("Packet on watch list -- filtering it");
		//TODO: create and send new packet
		packet.drop();
	}
	else{
		DEBUG("Packet NOT on watch list -- ignoring it");
		packet.accept();
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
		if(*it == p.get_ip_destination_address_s()){
			return true;
		}
	}

	return false;
}

void Attack_Handler::create_packet(){
	DEBUG("Creating new packet");
}

