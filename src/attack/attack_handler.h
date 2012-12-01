
#ifndef ATTACK_HANDLER_H_
#define ATTACK_HANDLER_H_

#include "core/handler.h"
#include "packet/tcppacket.h"
#include "common/option_parser.h"

#include <fstream>
#include <set>

class Attack_Handler : public Handler {
public:
	Attack_Handler();
	virtual ~Attack_Handler();

	virtual void parse_options(int argc, char* const argv[]);

	virtual void input(IPPacket& p);

private:
	std::string watch_list_name_;
	std::set<string> *watch_list;

	void load_watch_list();
	bool on_watch_list(TCPPacket p);
	bool is_http_response(TCPPacket p);

	TCPPacket create_packet(TCPPacket & other, TCPPacket & out);
};

#endif /* ATTACK_HANDLER_H_ */
