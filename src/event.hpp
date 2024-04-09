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
         * @brief The listeners subscribed to this manager
         */
        std::vector<std::unique_ptr<BaseEventListener>> listeners;

        /**
         * @brief Start the automatic event publisher
         * 
         * @return true on success
         * @return false on failure
         */
        bool startEventPublisher();

        /**
         * @brief Create the event queues
         * 
         * @return true on success
         * @return false on failure
         */
        bool createQueues();

    public:
        /**
         * @brief Construct a new Event Manager object
         * 
         * @param publishInterval How often the auto publisher will run, set to 0 to disable
         */
        EventManager(uint32_t publishInterval = 10);

        /**
         * @brief Registers a listener with the event manager
         * 
         * @tparam T The Type of event to listen for
         * @return ListenerId The Id of the listener
         */
        template <typename T> ListenerId registerListener();

        /**
         * @brief Registers a provided listener
         * 
         * @tparam T The type of event
         * @param listener A pointer to the listener
         * @return ListenerId The listener's id
         */
        template <typename T> ListenerId registerListener(std::unique_ptr<T> &listener);

        /**
         * @brief Registers a custom listener
         * 
         * @tparam T The type of the listener
         * @tparam Args The args to create it
         * @param args The Args
         * @return ListenerId The ID of the listener
         */
        template <typename T, typename ...Args> ListenerId registerCustomListener(Args ...args);

        /**
         * @brief Creates an Id Based Event Listener
         * 
         * @tparam Args Args for @ref IdBasedEventListener
         * @param args
         * @return ListenerId
         */
        template <typename ...Args> ListenerId registerIdBasedListener(Args ...args);

        /**
         * @brief Deregisters listener
         * 
         * @param id Listener Id
         * @return true on success
         * @return false on failure
         */
        bool deregisterListener(ListenerId id);

        /**
         * @brief manually Publishes queued events to listeners
         * 
         * @return true on success
         * @return false on failure
         */
        bool publish();

        /**
         * @brief Pushes event to event queues
         * @note this function will block if event queues are locked by mutexes, due to the publishing process
         * 
         * @tparam T Type of event, should extend @ref Event
         * @param event The event
         */
        template <typename T> void pushEvent(T event);

        /**
         * @brief Pushes event to event queues
         * @note starts separate thread that calls the @ref pushEvent function
         * 
         * @tparam T Type of event, should extend @ref Event
         * @param event The event
         */
        template <typename T> void threadPushEvent(T event);

        /**
         * @brief Attempts to push event to queue
         * 
         * @tparam T Event type
         * @param event 
         * @return true on success
         * @return false on failure
         */
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
}; // EventManager prototype

/**
 * @brief The Event class
 */
class Event {
    private:
        friend class BaseEventListener;
        friend class EventManager;

        uint64_t id;

    protected:
        std::chrono::time_point<std::chrono::system_clock> time;

        /**
         * @brief Generates and returns an event id
         * 
         * @return Event Id 
         */
        inline EventId generateId() {
            return EventManager::generateId();
        }

    public:
        /**
         * @brief Construct a new Event object
         */
        Event() {
            time = std::chrono::system_clock::now();
            this->id = this->generateId();
        }

        /**
         * @brief Construct a new Event object
         * 
         * @param id The id of the event
         */
        Event(int id) {
            time = std::chrono::system_clock::now();
            this->id = id;
        }

        /**
         * @brief Get the Event Id
         * 
         * @return The Event Id 
         */
        EventId getId() const {
            return id;
        }

        virtual ~Event() = default;

}; // Event

/**
 * @brief The base class for ID based events
 * @note relies on a hard coded 
 */
class IdBasedEvent : public Event {
    protected:

        /**
         * @brief This is the id that the listener will look for to identify it's events
         */
        EventTypeId eventTypeId = 0ULL;
    public:
        IdBasedEvent() = delete;

        /**
         * @brief Construct a new Id Based Event object
         * 
         * @param id Type Id
         */
        IdBasedEvent(EventTypeId id)
        : eventTypeId(id) {}

        /**
         * @brief Construct a new Id Based Event object
         * 
         * @param tid Type Id 
         * @param id Event Id
         */
        IdBasedEvent(EventTypeId tid, EventId id)
        : Event(id), eventTypeId(tid) {}

        /**
         * @brief Get the Type Id
         * @note this is now the @ref EventManager differentiates between different event types
         * 
         * @return EventTypeId 
         */
        virtual inline EventTypeId getTypeId() {
            return eventTypeId;
        }

        virtual ~IdBasedEvent() = default;
}; // IdBasedEvent

/**
 * @brief An Event that contains a payload for the id listener handlers
 * 
 * @tparam PayloadType Payload Type
 */
template <typename PayloadType> class PayloadIdBasedEvent : public IdBasedEvent {
    private:
        /**
         * @brief The payload of the event
         */
        PayloadType payload;
    public:
        PayloadIdBasedEvent() = delete;

        /**
         * @brief Construct a new Payload Id Based Event object
         * 
         * @param payload The payload
         * @private There has to be a better way to assign different type ids, I have considered using the string types that C++ generates but that seemed like it came with a large amount of overhead
         */
        PayloadIdBasedEvent(PayloadType payload) : IdBasedEvent(1ULL), payload(payload) {}

        /**
         * @brief Construct a new Payload Id Based Event
         * 
         * @param payload The payload
         * @param id The Event Type Id
         * @note this constructor is mainly for child classes
         */
        PayloadIdBasedEvent(PayloadType payload, EventTypeId tid) : IdBasedEvent(tid), payload(payload) {}

        /**
         * @brief Construct a new Payload Id Based Event
         * 
         * @param payload The Payload
         * @param tid The Event Type Id
         * @param id The Event Id
         */
        PayloadIdBasedEvent(PayloadType payload, EventTypeId tid, EventId id): IdBasedEvent(tid, id), payload(payload) {}
}; // PayloadIdBasedEvent

// Second event for debugging
class MyEvent : public Event {
    public:
        MyEvent() {}
}; // MyEvent

/**
 * @brief An Event with a payload
 * 
 * @tparam PayloadType The payload type
 */
template <typename PayloadType> class PayloadEvent : public Event {
    private:
        /**
         * @brief The Payload
         */
        PayloadType payload;
    public:
        /**
         * @brief Construct a new Payload Event
         * 
         * @param payload The Payload
         */
        PayloadEvent(PayloadType payload) : payload(payload) {}

        /**
         * @brief Construct a new Payload Event
         * 
         * @param payload The Payload
         * @param id The Event Id
         */
        PayloadEvent(PayloadType payload, EventId id) : payload(payload), Event(id) {}

        /**
         * @brief Get the Payload
         * 
         * @return The Payload
         */
        inline const PayloadType getPayload() {
            return payload;
        }
}; // PayloadEvent

/**
 * @brief Checks if a type is a child of a base
 * @note Works based on SFINAE
 * 
 * @tparam Base The Base
 * @tparam Child The Child
 */
template <typename Base, typename Child> struct isBaseOf {
    typedef int yes;
    typedef char no;

    static yes check(Base *);
    static no check(...);

    enum { value = sizeof(check(static_cast<Child *>(0))) == sizeof(yes) };
}; // isBaseOf

/**
 * @brief Event Error class, thrown if a exception happens in the event handling or managing
 */
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

        /**
         * @brief Number of listeners that exist
         */
        static uint64_t numberOfListeners;

    protected:
        /**
         * @brief The Id of the listener 
         */
        ListenerId id;

        /**
         * @brief This is the callback function for when an event is handled
         * 
         * @param event The Event Object
         */
        virtual void callback(const std::shared_ptr<Event> &event) const = 0;

        /**
         * @brief Checks if an event is the one that this listener is listening for
         * 
         * @param event The Event in question
         * @return true if the event belongs to this listener
         * @return false if the event doesn't belong to this listener
         */
        virtual bool myEvent(const std::shared_ptr<Event> &event) const = 0;

        /**
         * @brief Generates the listener's id
         * 
         * @return ListenerId 
         */
        inline ListenerId generateId() {
            return numberOfListeners++;
        }
    public:
        /**
         * @brief Construct a new Base Event Listener
         * @note generates the id
         */
        BaseEventListener() {
            this->id = generateId();
            print(2, "Created Listener " + std::to_string(this->id));
        }

        /**
         * @brief Construct a new Base Event Listener
         * 
         * @param id The listener id
         */
        BaseEventListener(ListenerId id) {
            this->id = id;
            print(2, "Created Listener " + std::to_string(this->id));
        }

        virtual ~BaseEventListener() = default;
        inline uint64_t getId() { return id; }
}; // BaseEventListener

uint64_t BaseEventListener::numberOfListeners = 0;

/**
 * @brief This is the generalized Event Listener
 * 
 * @tparam EventType 
 * @extends BaseEventListener
 */
template <typename EventType> class EventListener : public BaseEventListener {
    private:
        /**
         * @brief The default callback function
         * 
         * @param event The event
         */
        static void defaultCallbackFunction(const std::shared_ptr<EventType> &event) {
            print(1, "Event: " + std::to_string(event->getId()));
        }
    protected:
        using CallbackFunction = std::function<void (const std::shared_ptr<EventType> &)>;

        /**
         * @brief This is the callback function that will be called
         */
        CallbackFunction callbackFn;
    public:

        /**
         * @brief Construct a new Event Listener
         * @note Sets the callback function to the @ref defaultCallbackFunction
         */
        EventListener() {
            static_assert(isBaseOf<Event, EventType>::value);
            this->callbackFn = defaultCallbackFunction;
        }

        /**
         * @brief Construct a new Event Listener
         * 
         * @param callbackFn The callback function
         */
        EventListener(CallbackFunction callbackFn) {
            static_assert(isBaseOf<Event, EventType>::value);
            this->callbackFn = callbackFn;
        }

        ~EventListener() {};

        /**
         * @brief Checks if an event belongs to this listener
         * 
         * @param event The event
         * @return true If it is
         * @return false If not
         */
        bool myEvent(const std::shared_ptr<Event> &event) const override {
            return std::dynamic_pointer_cast<EventType>(event) != nullptr;
        }

        /**
         * @brief The function that will be called if @ref myEvent returns true
         * 
         * @param event The event
         */
        void callback(const std::shared_ptr<Event> &event) const override {
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

/**
 * @brief Id Based event listener
 */
class IdBasedEventListener : public BaseEventListener {
    private:
        EventTypeId type;

        using CallbackFunction = std::function<void (const std::shared_ptr<IdBasedEvent> &)>;
        CallbackFunction callbackFn;

        /**
         * @brief The default callback function
         * 
         * @param event Event
         */
        static void defaultCallbackFunction(const std::shared_ptr<IdBasedEvent> &event) {
            print(1, "Event: " + std::to_string(event->getId()));
        }
    public:
        IdBasedEventListener() = delete;

        /**
         * @brief Construct a new Id Based Event Listener object
         * 
         * @param type The type of 
         */
        IdBasedEventListener(EventTypeId type) {
            this->type = type;
            this->callbackFn = defaultCallbackFunction;
        }

        /**
         * @brief Construct a new Id Based Event Listener
         * 
         * @param type The Event Type
         * @param callbackFn The Callback Function
         */
        IdBasedEventListener(EventTypeId type, CallbackFunction callbackFn) {
            this->type = type;
            this->callbackFn = callbackFn;
        }

        ~IdBasedEventListener() {}

        /**
         * @brief The callback that will be called by the event manager
         * 
         * @param event The event
         */
        virtual inline void callback(const std::shared_ptr<Event> &event) const override {
            callbackFn(std::static_pointer_cast<IdBasedEvent>(event));
        }

        /**
         * @brief Checks if an event belongs to this listener
         * 
         * @param event The event
         * @return true if it is
         * @return false if not
         */
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