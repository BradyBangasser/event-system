#pragma once

// Abstract class
// Created 

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