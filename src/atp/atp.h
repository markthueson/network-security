/* 
 * File:   atp.h
 * Author: rbuck
 *
 * Created on July 13, 2010, 15:49 PM
 */

#ifndef _ATP_H
#define	_ATP_H

#include "core/handler.h"
#include "packet/udppacket.h"
#include "common/option_parser.h"

#include <fstream>

struct atphdr {
    u_int8_t protocol;
    u_int8_t version;
    
    u_int8_t fin:1;
    u_int8_t syn:1;
    u_int8_t rst:1;
    u_int8_t psh:1;
    u_int8_t ack:1;
    u_int8_t resend:1;
    u_int8_t sack_opt:1;
    u_int8_t sack_permission:1;

    u_int8_t sack_len;

    u_int32_t seq_num;
    u_int32_t ack_num;
    u_int32_t delay;
};

extern bool verbose_;

class ATP : public Handler {
public:
    ATP();
    ATP(const ATP& orig);
    virtual ~ATP();
    void postrouting(IPPacket & p);
    virtual void parse_options(int argc, char* const argv[]);
private:
    struct atphdr * get_atphdr(UDPPacket * packet);
    u_int32_t get_delay(void);
    void print(struct atphdr * header);
    int port_;
};

#endif	/* _ATP_H */

