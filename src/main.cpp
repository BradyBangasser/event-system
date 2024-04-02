#include <string>
#include <iostream>

#include "event.hpp"

int main() {
    EventManager manager(0);

    manager.registerListener<MyEvent>();
    // manager.registerListener<Event>();


    // Event event;
    // MyEvent event1;

    // manager.pushEvent(event);
    // // manager.publish();

    // manager.pushEvent(event1);
    // // manager.publish();

    // while(1);
    
    manager.registerIdBasedListener(0);

    return 0;
}