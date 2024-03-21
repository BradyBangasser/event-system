#pragma once

#include <queue>
#include <memory>
#include <thread>
#include <mutex>
#include <inttypes.h>
#include <chrono>
#include <list>
#include <algorithm>
#include <functional>

typedef uint64_t ListenerId;

class Event;
class EventManager;
class BaseEventListener;
template <typename T> class EventListener;

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
        static uint64_t numberOfEvents;

        typedef std::queue<std::shared_ptr<Event>> EventQueue;

        static constexpr uint32_t numberOfQueues = 2;

        std::vector<EventQueue> queues;
        std::unique_ptr<std::mutex[]> queueMutex;
        // in ms
        uint32_t publishInterval;

        std::vector<std::unique_ptr<BaseEventListener>> listeners;

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

        bool createQueues(uint32_t num) {
            for (int i = 0; i < num; i++) {
                queues.push_back(EventQueue());
                queueMutex = std::unique_ptr<std::mutex[]>(new std::mutex[numberOfQueues]); 
            }

            return true;
        }

    public:
        
        EventManager(uint32_t publishInterval = 10) {
            this->publishInterval = publishInterval;
            this->createQueues(numberOfQueues);

            if (publishInterval > 0) {
                startEventPublisher();
            }
        }

        template <typename T> ListenerId registerListener() {
            static_assert(isBaseOf<Event, T>::value);
            std::unique_ptr<EventListener<T>> listener = std::make_unique<EventListener<T>>();
            ListenerId lid = listener->id;
            listeners.push_back(std::move(listener));
            return lid;
        }

        // Not tested
        template <typename T> ListenerId registerListener(std::unique_ptr<T> &listener) {
            static_assert(isBaseOf<BaseEventListener, T>::value);
            listeners.push_back(std::move(listener));
            return listeners->id;
        }

        // Not tested
        template <typename T, typename ...Args> ListenerId registerCustomListener(Args ...args) {
            static_assert(isBaseOf<BaseEventListener, T>::value);
            std::unique_ptr<T> listener = std::make_unique<T>(std::forward(args)...);
            ListenerId lid = listener.id;
            listeners.push_back(std::move(listener));
            return lid;
        }

        void deregisterListener(ListenerId id) {
            this->listeners.erase(std::find_if(this->listeners.begin(), this->listeners.end(), [](std::unique_ptr<BaseEventListener) {

            }));
        }

        bool publish() {
            static uint32_t i, j, listenersLength = listeners.size();
            
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

        /**
         * @brief Get an new event id
         * 
         * @warning Overflow not handled, do not use for calculations
         * @return uint64_t 
         */
        static inline uint64_t getEventId() {
            return numberOfEvents++;
        }
};

class BaseEventListener {
    private:
        friend class EventManager;
        ListenerId id;

    protected:
        virtual void callback(const std::shared_ptr<Event> &event) const = 0;
        virtual bool myEvent(const std::shared_ptr<Event> &event) const = 0;

        inline uint64_t generateId() {
            return 0xffffffffffffffff;
        }
    public:
        BaseEventListener() {

        }

        virtual ~BaseEventListener() = default;
        inline uint64_t getId() { return id; }
};

template <typename EventType> class EventListener : public BaseEventListener {
    private:
        using CallbackFunction = std::function<void (const std::shared_ptr<EventType> &)>;
        CallbackFunction callbackFn;
    public:
        EventListener(CallbackFunction callbackFn) {
            this->callbackFn = callbackFn;
        }

        bool myEvent(const std::shared_ptr<Event> &event) const override { 
            return std::dynamic_pointer_cast<EventType>(event) != nullptr;
        }

        void callback(const std::shared_ptr<Event> &event) const override {
            callbackFn(std::dynamic_pointer_cast<EventType>(event));
        }
};

class Event {
    private:
        friend class BaseEventListen;
        friend class EventManager;

        std::chrono::time_point<std::chrono::system_clock> time;
        uint64_t id;

        inline uint64_t generateId() {
            return EventManager::getEventId();
        }

    public:
        Event() {
            time = std::chrono::system_clock::now();
            this->id = this->generateId();
        }

        Event(int id) {
            time = std::chrono::system_clock::now();
            this->id = id;
        }

        uint64_t getId() const {
            return id;
        }

        virtual ~Event() = default;

};

class MyEvent : public Event {
    public:
        MyEvent() {

        }
};

template <typename PayloadType> class PayloadEvent : public Event {

};