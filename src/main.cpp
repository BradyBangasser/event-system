#include <string>

#include "event-listener.hpp"
#include "event-manager.hpp"
#include "event.hpp"

int main() {
    EventManager manager;

    std::cout << isBaseOf<Event, MyEvent>::value << std::endl;

    // manager.registerListener<MyEvent>();
    // manager.registerListener<Event>();

    // Event event;
    // MyEvent event1;

    // manager.push(event);
    // manager.publish();

    // manager.push(event1);
    // manager.publish();

    return 0;
}