#include "handler_factory.h"

Handler* create_handler(std::string name) {
    if (name == "default") {
        return new Handler();
    }
    if (name == "test") {
        return new TestHandler();
    }
    if (name == "atp") {
        return new ATP();
    }
    if (name == "tcp_atp") {
        return new TCP_ATP();
    }
}
