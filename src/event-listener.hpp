#pragma once

#include <functional>
#include <memory>
#include <iostream>

#include "event.hpp"

class BaseEventListener {
    public:
        virtual ~BaseEventListener() = default;
        virtual void callback(const std::shared_ptr<Event> &event) const = 0;
        virtual bool myEvent(const std::shared_ptr<Event> &event) const = 0;
};

template <typename EventType> class EventListener : public BaseEventListener {
    public:
        EventListener() = default;
        using CallbackFunction = std::function<void (const std::shared_ptr<EventType> &)>;
        CallbackFunction cb = [](const std::shared_ptr<EventType> &event) {
            std::cout << "here " << event->getId() << std::endl;
        };
        bool myEvent(const std::shared_ptr<Event> &event) const override {
            std::cout << event->getId() << std::endl;
            return std::dynamic_pointer_cast<EventType>(event) != nullptr;
        }

        void callback(const std::shared_ptr<Event> &event) const override {
            cb(std::dynamic_pointer_cast<EventType>(event));
        }
};