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
#include <iostream> 

/**
 * @brief The level of debugging statements
 * [0-2]
 */
#define DEBUG_LEVEL 3

/**
 * @brief Mutex to protect the standard out
 */
static std::mutex m_printer;

/**
 * @brief Thread safe printing
 * 
 * @param level The debug level of the message
 * @param message The message to print
 */
static void print(uint8_t level, std::string message) {
    if (level <= DEBUG_LEVEL) {
        m_printer.lock();
        std::cout << message << "\n";
        m_printer.unlock();
    }
}

/**
 * @brief The id of the listener
 */
using ListenerId = uint64_t;

/**
 * @brief The Event Id
 * 
 */
using EventId = uint64_t;

/**
 * @brief The type of the id for ID based events
 * 
 */
using EventTypeId = uint64_t;

// Needed for EventManager
class Event;
class BaseEventListener;
class IdBasedEvent;

/**
 * @brief This manages all of the event listeners and events
 */
class EventManager {
    private:
        static uint64_t numberOfEvents;

        /**
         * @brief This is the type for the event queues
         */
        using EventQueue = std::queue<std::shared_ptr<Event>>;

        /**
         * @brief The number of event queues that the manager will use, 2 is usually fine
         * @note The dual queue system is to prevent delays while one of the queues if locked due to the publishing process
         */
        static constexpr uint32_t numberOfQueues = 2;

        /**
         * @brief These are the event queues
         */
        std::vector<EventQueue> queues;
        /**
         * @brief these are the mutexes to lock the queues
         */
        std::unique_ptr<std::mutex []> queueMutex;

        /**
         * @brief How often the auto publisher will publish the queued events (milliseconds)
         * @note if set to 0, the auto publisher will be disabled
         */
        uint32_t publishInterval;

        /**
         * @brief 
         * 
         */
        std::vector<std::unique_ptr<BaseEventListener>> listeners;

        bool startEventPublisher();
        bool createQueues();

    public:
        EventManager(uint32_t publishInterval = 10);

        template <typename T> ListenerId registerListener();
        template <typename T> ListenerId registerListener(std::unique_ptr<T> &listener);
        template <typename T, typename ...Args> ListenerId registerCustomListener(Args ...args);
        template <typename ...Args> ListenerId registerIdBasedListener(Args ...args);

        bool deregisterListener(ListenerId id);
        bool publish();

        template <typename T> void pushEvent(T event);
        template <typename T> void threadPushEvent(T event);
        template <typename T> bool tryPushEvent(T event);

        /**
         * @brief Get an new event id
         * 
         * @warning Overflow not handled, do not use for calculations
         * @return uint64_t 
         */
        static inline EventId generateId() { 
            return numberOfEvents++;
        }
}; // EventManager

class Event {
    private:
        friend class BaseEventListener;
        friend class EventManager;

        uint64_t id;

    protected:
        std::chrono::time_point<std::chrono::system_clock> time;

        inline uint64_t generateId() {
            return EventManager::generateId();
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

class IdBasedEvent : public Event {
    protected:

        /**
         * @brief This is the id that the listener will look for to identify it's events
         */
        EventTypeId eventTypeId = 0ULL;
    public:
        IdBasedEvent() = delete;

        IdBasedEvent(EventTypeId id) {
            this->eventTypeId = id;
        }

        virtual inline EventTypeId getTypeId() {
            return eventTypeId;
        }

        virtual ~IdBasedEvent() = default;
}; // IdBasedEvent

template <typename PayloadType> class PayloadIdBasedEvent : public IdBasedEvent {
    private:
        PayloadType payload;
    public:

        PayloadIdBasedEvent() = delete;

        // There has to be a better way to do this
        PayloadIdBasedEvent(PayloadType payload) : IdBasedEvent(1ULL) {
            this->payload = payload;
        }
}; // PayloadIdBasedEvent

// Second event for debugging
class MyEvent : public Event {
    public:
        MyEvent() {}
}; // MyEvent

template <typename PayloadType> class PayloadEvent : public Event {
    private:
        PayloadType payload;
    public:
        PayloadEvent(PayloadType payload) {
            this->payload = payload;
        }

        inline const PayloadType getPayload() {
            return payload;
        }
}; // PayloadEvent

// Cool little SFINAE
template <typename Base, typename Child> struct isBaseOf {
    typedef int yes;
    typedef char no;

    static yes check(Base *);
    static no check(...);

    enum { value = sizeof(check(static_cast<Child *>(0))) == sizeof(yes) };
};

class EventError : public std::exception {
    private:
        std::string message;
    public:
        EventError() {
            this->message = "Default Error Message";
        }

        EventError(std::string message) {
            this->message = message;
        }

        ~EventError() = default;
        const char *what() const noexcept {
            return message.c_str();
        }
}; // EventError

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
            print(2, "Created Listener " + std::to_string(this->id));
        }

        BaseEventListener(ListenerId id) {
            this->id = id;
            print(2, "Created Listener " + std::to_string(this->id));
        }

        virtual ~BaseEventListener() = default;
        inline uint64_t getId() { return id; }
}; // BaseEventListener

uint64_t BaseEventListener::numberOfListeners = 0;

template <typename EventType> class EventListener : public BaseEventListener {
    private:
        using CallbackFunction = std::function<void (const std::shared_ptr<EventType> &)>;
        CallbackFunction callbackFn;

        static void defaultCallbackFunction(const std::shared_ptr<EventType> &event) {
            print(1, "Event: " + std::to_string(event->getId()));
        }
    public:
        EventListener() {
            static_assert(isBaseOf<Event, EventType>::value);
            this->callbackFn = defaultCallbackFunction;
            // FOR DEBUGGING
            this->callbackFn(std::make_shared<EventType>());
        }

        EventListener(CallbackFunction callbackFn) {
            static_assert(isBaseOf<Event, EventType>::value);
            this->callbackFn = callbackFn;
        }

        ~EventListener() {};

        bool myEvent(const std::shared_ptr<Event> &event) const override {
            return std::dynamic_pointer_cast<EventType>(event) != nullptr;
        }

        virtual void callback(const std::shared_ptr<Event> &event) const override {
            try {
                callbackFn(std::static_pointer_cast<EventType>(event));
            } catch (const std::exception &err) {
                print(0, "Error: " + std::string(err.what()));
            } catch (...) {
                std::exception_ptr err = std::current_exception();

                if (err != nullptr) {
                    std::rethrow_exception(err);
                } else {
                    throw EventError("Unknown Error thrown");
                }
            }
        }
}; // EventListener

class IdBasedEventListener : public BaseEventListener {
    private:
        EventTypeId type;

        using CallbackFunction = std::function<void (const std::shared_ptr<IdBasedEvent> &)>;
        CallbackFunction callbackFn;

        static void defaultCallbackFunction(const std::shared_ptr<IdBasedEvent> &event) {
            print(1, "Event: " + std::to_string(event->getId()));
        }
    public:
        IdBasedEventListener() = delete;

        IdBasedEventListener(EventTypeId type) {
            this->type = type;
            this->callbackFn = defaultCallbackFunction;
        }


        IdBasedEventListener(EventTypeId type, CallbackFunction callbackFn) {
            this->type = type;
            this->callbackFn = callbackFn;
        }

        ~IdBasedEventListener() {}

        virtual inline void callback(const std::shared_ptr<Event> &event) const override {
            callbackFn(std::static_pointer_cast<IdBasedEvent>(event));
        }

        inline bool myEvent(const std::shared_ptr<Event> &event) const override {
            std::shared_ptr<IdBasedEvent> castedEvent = std::dynamic_pointer_cast<IdBasedEvent>(event);
            return castedEvent != nullptr && castedEvent->getTypeId() == this->type;
        }

}; // IdBasedEventListener

// __ Event Manager Impl __

uint64_t EventManager::numberOfEvents = 0;

bool EventManager::startEventPublisher() {
    std::thread([this]() {
        std::chrono::milliseconds waitTime(this->publishInterval);
        while (1) {
            std::this_thread::sleep_for(waitTime);
            if (!this->publish()) {
                throw EventError("Failed to publish");
            }

        }
    }).detach();

    return true;
}

bool EventManager::createQueues() {
    for (int i = 0; i < numberOfQueues; i++) {
        queues.push_back(EventQueue());
        queueMutex = std::unique_ptr<std::mutex []>(new std::mutex[numberOfQueues]); 
    }

    return true;
}

EventManager::EventManager(uint32_t publishInterval) {
    this->publishInterval = publishInterval;
    this->createQueues();

    if (publishInterval > 0) {
        startEventPublisher();
    }
}

template <typename T> ListenerId EventManager::registerListener() {
    print(0, "Register");
    static_assert(isBaseOf<Event, T>::value);
    std::unique_ptr<EventListener<T>> listener = std::make_unique<EventListener<T>>();
    ListenerId lid = listener->id;
    listeners.push_back(std::move(listener));
    print(0, std::to_string(listeners.size()));
    return lid;
}

// Not tested
template <typename T> ListenerId EventManager::registerListener(std::unique_ptr<T> &listener) {
    static_assert(isBaseOf<BaseEventListener, T>::value);
    listeners.push_back(std::move(listener));
    return listener->id;
}

// Not tested
template <typename T, typename ...Args> ListenerId EventManager::registerCustomListener(Args ...args) {
    static_assert(isBaseOf<BaseEventListener, T>::value);
    std::unique_ptr<T> listener = std::make_unique<T>(std::forward(args)...);
    ListenerId lid = listener->id;
    listeners.push_back(std::move(listener));
    return lid;
}

template <typename ...Args> ListenerId EventManager::registerIdBasedListener(Args ...args) {
    std::unique_ptr<IdBasedEventListener> listener = std::make_unique<IdBasedEventListener>(std::forward<Args>(args)...);
    ListenerId lid = listener->id;
    listeners.push_back(std::move(listener));
    return lid;
}

bool EventManager::deregisterListener(ListenerId id) {
    uint32_t i;
    for (i = 0; i < this->listeners.size(); i++) {
        if (this->listeners[i]->id == id) {
            this->listeners.erase(this->listeners.begin() + i, this->listeners.end() + i);
            return true;
        }
    }
    
    return false;
}

bool EventManager::publish() {
    static uint32_t i, j, listenersLength = listeners.size();
    
    EventQueue *currentQueue = NULL;

    for (i = 0; i < numberOfQueues; i++) {
        this->queueMutex[i].lock();

        currentQueue = &this->queues[i];

        while (currentQueue->size() > 0) {
            std::shared_ptr<Event> event = currentQueue->front();
            currentQueue->pop();

            for (j = 0; j < listenersLength; j++) {
                print(0, std::to_string(this->listeners[j]->myEvent(event)));
                if (this->listeners[j]->myEvent(event)) {
                    print(0, "Event: " + std::to_string(event->getId()));
                    this->listeners[j]->callback(event);
                }
            }
        }

        this->queueMutex[i].unlock();
    }

    return true;
}

template <typename T> void EventManager::pushEvent(T event) {
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

template <typename T> bool EventManager::tryPushEvent(T event) {
    static_assert(isBaseOf<Event, T>::value);
    for (int i = 0; i < numberOfQueues; i++) {
        if (queueMutex[i].try_lock()) {
            queues[i].push(event);
            return true;
        }
    }

    return false;
}

template <typename T> void EventManager::threadPushEvent(T event) {
    static_assert(isBaseOf<Event, T>::value);
    std::thread([this, event]() {
        this->queueMutex[0].lock();
        this->queues[0].push(event);
    }).detach();
}