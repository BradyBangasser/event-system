#pragma once

#include <queue>
#include <memory>
#include <thread>
#include <mutex>
#include <cinttypes>
#include <chrono>
#include <list>

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

// TODO Add string/int id based events
class EventManager {
    private:
        typedef std::queue<std::shared_ptr<Event>> EventQueue;

        static constexpr uint_t numberOfQueues = 2;

        std::vector<EventQueue> queues;
        std::unique_ptr<std::mutex[]> queueMutex;
        // in ms
        uint_t publishInterval;

        std::vector<std::unique_ptr<BaseEventListener>> listeners;

        friend class EventError;

        // For debugging

        std::mutex printerMutex;
        template <typename T> void print(T arg) {
            this->printerMutex.lock();
            std::cout << arg << "\n";
            this->printerMutex.unlock();
        }

        void startEventPublisher() {
            std::thread([this]() {
                std::chrono::milliseconds waitTime(this->publishInterval);
                while (1) {
                    if (!this->publish()) {
                        throw EventError();
                    }

                    std::this_thread::sleep_for(waitTime);
                }
            }).detach();
        }

        bool createQueues(uint_t num) {
            for (int i = 0; i < num; i++) {
                queues.push_back(EventQueue());
                queueMutex = std::unique_ptr<std::mutex[]>(new std::mutex[numberOfQueues]); 
            }

            return true;
        }

    public:
        
        EventManager(uint_t publishInterval = 10) {
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
            static uint_t i, j, listenersLength = listeners.size();
            
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

        template <typename T> bool tryPushEvent(T event) {
            static_assert(isBaseOf<Event, T>::value);
            for (int i = 0; i < numberOfQueues; i++) {
                if (queueMutex[i].try_lock()) {
                    queues[i].push(event);
                    return true;
                }
            }

            return false;
        }

        template <typename T> void threadPushEvent(T event) {
            static_assert(isBaseOf<Event, T>::value);
            std::thread([this, event]() {
                this->queueMutex[0].lock();
                this->queues[0].push(event);
            }).detach();
        }
};

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

class Event {
    private:

    public:
        Event() {

        }

        virtual char getId() const {
            return 'a';
        }

        virtual ~Event() = default;

};

class MyEvent : public Event {
    public:
        MyEvent() {

        }

        virtual char getId() const override {
            return 'b';
        }
};