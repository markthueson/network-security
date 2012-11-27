#include "tcp_atp.h"

TCP_ATP::TCP_ATP() : port_(0){
    if (verbose_) cout << "TCP_ATP Handler" << endl;
}

TCP_ATP::TCP_ATP(const TCP_ATP& orig) {

}

TCP_ATP::~TCP_ATP() {

}

void TCP_ATP::parse_options(int argc, char* const argv[]) {
    const char * port = "port";

    static struct option long_options[] = {
        {port, required_argument, NULL, 0},
        {0, 0, 0, 0}
    };

    OptionParser options;
    options.parse(argc, argv, long_options);

    if(options.present(port)) {
        port_ = atoi(options.argument(port));
    }
    if (verbose_) cout << "Port set to: " << port_ << endl;
}

void TCP_ATP::postrouting(IPPacket & p) {
    if (verbose_) cout << "Entering Output" << endl;

    if (p.get_ip_protocol() != TCPATP) {
        if (verbose_) cout << "Accepting non TCP Packet (" << (int)p.get_ip_protocol() << ")" << endl;
        p.accept();
        return;
    }

    TCPPacket packet(p, false);


    if (packet.get_tcp_source_port() != port_ && packet.get_tcp_destination_port() != port_ && port_ != 0) {
    	if (verbose_) cout << "Source and/or destination port do not match" << endl;
    	packet.accept();
        return;
    }

    struct tcp_atphdr * header = get_tcp_atphdr(&packet);

    if (verbose_) print(header);

    u_int32_t header_delay = ntohl(header->max_delay);
    u_int32_t delay = get_delay();

    if (verbose_) cout << "Delay from proc is: " << delay << endl;
    if (verbose_) cout << "Delay in header is: " << header_delay << endl;

    if (delay > header_delay) {
        header->max_delay = htonl(delay);
        if (verbose_) cout << "Set delay in packet to: " << ntohl(header->max_delay) << endl;
        packet.recalculate_tcp_checksum();
    }

    if (verbose_) cout << "Accepting packet finally" << endl;
    packet.accept();
}

struct tcp_atphdr * TCP_ATP::get_tcp_atphdr(TCPPacket * packet) {
    unsigned char * ptr = (unsigned char *) packet->get_next_header() + packet->get_tcp_length_bytes();
    return (struct tcp_atphdr *) ptr;
}

u_int32_t TCP_ATP::get_delay(void) {
    char str[200];
    fstream file_op("/proc/ath5k/Da", ios::in);
    u_int32_t value = 0;

    while (file_op >> str) {
        value = atoi(str);
    }

    file_op.close();
    return value;
}

void TCP_ATP::print(struct tcp_atphdr * header) {
	cout << "-----Header-----" << endl;
    cout << "Max Delay: " << ntohl(header->max_delay) << endl;
    cout << "Average Delay: " << ntohl(header->average_delay) << endl;
    cout << "----------------" << endl;
    cout << endl;
}
