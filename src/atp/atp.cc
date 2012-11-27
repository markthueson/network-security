#include "atp.h"

ATP::ATP() {
    if (verbose_) cout << "ATP Handler" << endl;
}

ATP::ATP(const ATP& orig) {

}

ATP::~ATP() {

}

void ATP::parse_options(int argc, char* const argv[]) {
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

void ATP::postrouting(IPPacket & p) {
    if (verbose_) cout << "Entering Output" << endl;

    if (p.get_ip_protocol() != UDP) {
        if (verbose_) cout << "Accepting non UDP Packet" << endl;
        p.accept();
        return;
    }

    UDPPacket packet(p, false);

    if (packet.get_udp_source_port() != port_ && packet.get_udp_destination_port() != port_) {
        packet.accept();
        return;
    }

    struct atphdr * header = get_atphdr(&packet);
    print(header);

    if (header->sack_opt) {
        if (verbose_) cout << "SACK Option set, accepting packet." << endl;
        p.accept();
        return;
    }

    u_int32_t header_delay = ntohl(header->delay);
    u_int32_t delay = get_delay();

    if (verbose_) cout << "Delay from proc is: " << delay << endl;
    if (verbose_) cout << "Delay in header is: " << header_delay << endl;

    if (delay > header_delay) {
        header->delay = htonl(delay);
        if (verbose_) cout << "Set delay in packet to: " << ntohl(header->delay) << endl;
        packet.recalculate_udp_checksum();
    }

    if (verbose_) cout << "Accepting packet finally" << endl;
    packet.accept();
}

struct atphdr * ATP::get_atphdr(UDPPacket * packet) {
    unsigned char * ptr = (unsigned char *) packet->udp();
    ptr += sizeof (struct udphdr);
    return (struct atphdr *) ptr;
}

u_int32_t ATP::get_delay(void) {
    char str[200];
    fstream file_op("/proc/ath5k/Da", ios::in);
    u_int32_t value;

    while (file_op >> str) {
        value = atoi(str);
    }

    file_op.close();
    return value;
}

void ATP::print(struct atphdr * header) {
    if (verbose_) {
        cout << "Protocol " << (int) header->protocol << endl;
        cout << "Version " << (int) header->version << endl;
        cout << "Sack Length " << (int) header->sack_len << endl;
        cout << "Sequence # " << ntohl(header->seq_num) << endl;
        cout << "ACK # " << ntohl(header->ack_num) << endl;
        cout << "Delay: " << ntohl(header->delay) << endl;

        cout << "Sack Permission: " << (int) header->sack_permission << endl;
        cout << "Sack Opt: " << (int) header->sack_opt << endl;
        cout << "Resend: " << (int) header->resend << endl;
        cout << "ACK: " << (int) header->ack << endl;
        cout << "PSH: " << (int) header->psh << endl;
        cout << "RST: " << (int) header->rst << endl;
        cout << "SYN: " << (int) header->syn << endl;
        cout << "FIN: " << (int) header->fin << endl;
        cout << endl;
    }
}