#include "server.h"

int main(int argc, char* argv[]) {
    Server server;
    
    if (!server.init(argc, argv)) {
        return 1;
    }
    
    if (!server.start()) {
        return 1;
    }
    
    return 0;
}
