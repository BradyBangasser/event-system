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
#include <string>

/**
 * @brief The level of debugging statements
 * [0-2]
 */
#define DEBUG_LEVEL 1

static std::mutex m_printer;
static void print(uint8_t level, std::string message) {
    if (level <= DEBUG_LEVEL) {
        m_printer.lock();
        std::cout << message << "\n";
        m_printer.unlock();
    }
}

typedef uint64_t ListenerId;

class Event;
class EventManager;
class BaseEventListener;

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

/**
 * @brief This is the base event listener class, all event listeners extend this class
 */
class BaseEventListener {
    private:
        friend class EventManager;

        static uint64_t numberOfListeners;

    protected:
        ListenerId id;

        virtual void callback(const std::shared_ptr<Event> &event) const = 0;
        virtual bool myEvent(const std::shared_ptr<Event> &event) const = 0;

        inline ListenerId generateId() {
            return numberOfListeners++;
        }
    public:
        BaseEventListener() {
            this->id = generateId();
            print(2, "Created Listener " + this->id);
        }

        BaseEventListener(ListenerId id) {
            this->id = id;
            print(2, "Created Listener " + this->id);
        }

        virtual ~BaseEventListener() = 0;
        inline uint64_t getId() { return id; }
}; // BaseEventListener

uint64_t BaseEventListener::numberOfListeners = 0;

template <typename EventType> class EventListener : public BaseEventListener {
    private:
        using CallbackFunction = std::function<void (const std::shared_ptr<EventType> &)>;
        CallbackFunction callbackFn;

        static void defaultCallbackFunction(const std::shared_ptr<EventType> &event) {
            print("Event: " + std::to_string(event->getId()));
        }
    public:
        EventListener() {
            static_assert(isBaseOf<Event, EventType>::value);
            this->callbackFn = defaultCallbackFunction;
        }

        EventListener(CallbackFunction callbackFn) : BaseEventListener() {
            static_assert(isBaseOf<Event, EventType>::value);
            this->callbackFn = callbackFn;
        }

        bool myEvent(const std::shared_ptr<Event> &event) const override { 
            return std::dynamic_pointer_cast<EventType>(event) != nullptr;
        }

        void callback(const std::shared_ptr<Event> &event) const override {
            callbackFn(std::dynamic_pointer_cast<EventType>(event));
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
            return listener->id;
        }

        // Not tested
        template <typename T, typename ...Args> ListenerId registerCustomListener(Args ...args) {
            static_assert(isBaseOf<BaseEventListener, T>::value);
            std::unique_ptr<T> listener = std::make_unique<T>(std::forward(args)...);
            ListenerId lid = listener.id;
            listeners.push_back(std::move(listener));
            return lid;
        }

        bool deregisterListener(ListenerId id) {
            uint32_t i;
            for (i = 0; i < this->listeners.size(); i++) {
                if (this->listeners[i]->id == id) {
                    this->listeners.erase(this->listeners.begin() + i, this->listeners.end() + i);
                    return true;
                }
            }
            
            return false;
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
}; // EventManager

uint64_t EventManager::numberOfEvents = 0;

class Event {
    private:
        friend class BaseEventListener;
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

// Second event for debugging
class MyEvent : public Event {
    public:
        MyEvent() {

        }
};

template <typename PayloadType> class PayloadEvent : public Event {
    private:
        PayloadType payload;
    public:
        PayloadEvent(PayloadType payload) : Event() {
            this->payload = payload;
        }

        inline const PayloadType getPayload() {
            return payload;
        }
};