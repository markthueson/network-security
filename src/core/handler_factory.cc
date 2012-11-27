#include "handler_factory.h"

Handler* create_handler(std::string name) {
    if (name == "attack") {
        return new Attack_Handler();
    }
    else {
    	return new Handler();
    }
}
