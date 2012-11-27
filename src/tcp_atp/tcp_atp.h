/*
 * File:   atp.h
 * Author: rbuck
 *
 * Created on July 13, 2010, 15:49 PM
 */

#ifndef _TCP_ATP_H
#define	_TCP_ATP_H

#include "core/handler.h"
#include "packet/tcppacket.h"
#include "common/option_parser.h"

#include <fstream>

struct tcp_atphdr {
	u_int32_t max_delay;
	u_int32_t average_delay;
};

extern bool verbose_;

class TCP_ATP : public Handler {
public:
	TCP_ATP();
	TCP_ATP(const TCP_ATP& orig);

    virtual ~TCP_ATP();

    void postrouting(IPPacket & p);

    virtual void parse_options(int argc, char* const argv[]);

private:
    struct tcp_atphdr * get_tcp_atphdr(TCPPacket * packet);

    u_int32_t get_delay(void);

    void print(struct tcp_atphdr * header);

    int port_;
};

#endif	/* _TCP_ATP_H */

