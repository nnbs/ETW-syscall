#pragma once
#include <iostream>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <thread>
#include "EtwReceiver.h"

class ThreadSafeQueue {
private:
    std::queue<std::shared_ptr<EventObject>> queue;
    std::mutex mtx;
    std::condition_variable cv;
    bool stop = false;


public:
    void push(std::shared_ptr<EventObject> value) {
        std::unique_lock<std::mutex> lock(mtx);
        queue.push(value);
        cv.notify_one();
    }

    std::shared_ptr<EventObject> pop() {
        std::unique_lock<std::mutex> lock(mtx);
        cv.wait(lock, [this] { return !queue.empty() || stop; });
        if (stop && queue.empty()) return NULL;

        std::shared_ptr<EventObject> value = queue.front();
        queue.pop();
        return value;
    }

    bool empty() {
        return queue.empty();
    }

    void shutdown() {
        std::lock_guard<std::mutex> lock(mtx);
        stop = true;
        cv.notify_all();
    }

};
