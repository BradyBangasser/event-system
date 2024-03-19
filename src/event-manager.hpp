#pragma once

#include <queue>
#include <memory>
#include <thread>
#include <mutex>
#include <cinttypes>
#include <chrono>
#include <list>

#include "event.hpp"
#include "event-listener.hpp"

typedef unsigned int uint_t;
typedef unsigned char ushort_t;

// Cool little SFINAE
template <typename Base, typename Child> struct isBaseOf {
    typedef int yes;
    typedef char no;

    static yes check(Base *);
    static no check(...);

    enum { value = sizeof(check(static_cast<Child *>(0))) == sizeof(yes) };
};

class EventError : public std::exception {
    public:
        ~EventError() = default;
        const char *what() const noexcept {
            return "Aw nuts";
        }
};

class EventManager {
    private:
        typedef std::queue<std::shared_ptr<Event>> EventQueue;

        static constexpr uint numberOfQueues = 2;

        std::vector<EventQueue> queues;
        std::unique_ptr<std::mutex[]> queueMutex;
        // in ms
        uint publishInterval;

        std::vector<std::unique_ptr<BaseEventListener>> listeners;

        friend class EventError;

        // For debugging

        std::mutex printerMutex;
        template <typename T> void print(T arg) {
            this->printerMutex.lock();
            std::cout << arg << "\n";
            this->printerMutex.unlock();
        }

        // Not Tested
        void startEventPublisher() {
            std::thread([this]() {
                std::chrono::milliseconds waitTime(this->publishInterval);
                while (1) {
                    if (!this->publish()) {
                        throw EventError();
                    }
                    // this->print("Here");

                    std::this_thread::sleep_for(waitTime);
                }
            }).detach();
        }

        bool createQueues(uint num) {
            for (int i = 0; i < num; i++) {
                queues.push_back(EventQueue());
                queueMutex = std::unique_ptr<std::mutex[]>(new std::mutex[numberOfQueues]); 
            }

            return true;
        }

    public:
        
        EventManager(uint publishInterval = 10) {
            this->publishInterval = publishInterval;
            this->createQueues(numberOfQueues);

            if (publishInterval > 0) {
                startEventPublisher();
            }
        }

        template <typename T> void registerListener() {
            static_assert(isBaseOf<Event, T>::value);
            listeners.push_back(std::move(std::make_unique<EventListener<T>>()));
        }

        // Not tested
        template <typename T> void registerListener(std::unique_ptr<T> &listener) {
            static_assert(isBaseOf<BaseEventListener, T>::value);
            listeners.push_back(std::move(listener));
        }

        // Not tested
        template <typename T, typename ...Args> void registerCustomListener(Args ...args) {
            static_assert(isBaseOf<BaseEventListener, T>::value);
            listeners.push_back(std::move(std::make_unique<T>(std::forward(args)...)));
        }

        bool publish() {
            print("Here");
            static uint i, j, listenersLength = listeners.size();
            
            EventQueue *currentQueue = NULL;

            for (i = 0; i < numberOfQueues; i++) {
                this->queueMutex[i].lock();

                currentQueue = &this->queues[i];

                while (currentQueue->size() > 0) {
                    std::shared_ptr<Event> event = currentQueue->front();
                    currentQueue->pop();

                    for (j = 0; j < listenersLength; j++) {
                        if (this->listeners[j]->myEvent(event)) {
                            this->listeners[j]->callback(event);
                        }
                    }
                }

                this->queueMutex[i].unlock();
            }

            return true;
        }


        template <typename T> void pushEvent(T event) {
            static_assert(isBaseOf<Event, T>::value);

            static int i = -1;
            while (1) {
                i = ++i % numberOfQueues;

                if (this->queueMutex[i].try_lock()) {

                    this->queues[i].push(std::move(std::make_shared<T>(event)));
                    
                    this->queueMutex[i].unlock();
                    return;
                }
            }
        }

        bool tryPushEvent() {

        }

        void threadPushEvent() {

        }
};