#include <string>
#include <iostream>

#include "event-listener.hpp"
#include "event-manager.hpp"
#include "event.hpp"

int main() {
    EventManager manager(100);

    manager.registerListener<MyEvent>();
    manager.registerListener<Event>();


    Event event;
    MyEvent event1;

    manager.pushEvent(event);
    // manager.publish();

    manager.pushEvent(event1);
    // manager.publish();

    while(1);

    return 0;
}