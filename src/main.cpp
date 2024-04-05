#include <string>
#include <iostream>

#include "event.hpp"

int main() {
    EventManager manager;

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

    manager.pushEvent(MyEvent());

    while(1);

    return 0;
}