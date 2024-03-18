#pragma once

#include <queue>
#include <memory>
#include <thread>

#include "event.hpp"
#include "event-listener.hpp"

// Cool little SFINAE
template <typename Base, typename Child> struct isBaseOf {
    typedef int yes;
    typedef char no;

    static yes check(Base*);
    static no check(...);

    enum { value = sizeof(check(static_cast<Child*>(0))) == sizeof(yes) };
};

class EventManager {
    private:
        std::queue<std::shared_ptr<Event>> events;
        std::vector<std::unique_ptr<BaseEventListener>> listeners;

        void startEventPublisher(uint interval) {
            std::thread([]() {

            }).detach();
        }

    public:
        template <typename T> inline void push(T &event) {
            events.push(std::move(std::make_shared<T>(event)));
        }

        template <typename T, typename ...Args> void registerListener(Args... args) {
            // static_assert()
            listeners.push_back(std::make_unique<EventListener<T>>(std::forward<Args>(args)...));
        }

        void publish() {
            std::shared_ptr<Event> event;
            while (!events.empty()) {
                event = events.front();
                events.pop();
                
                for (std::unique_ptr<BaseEventListener> &listener : listeners) {
                    if (listener->myEvent(event)) {
                        listener->callback(event);
                    }
                }
            }
        }
};