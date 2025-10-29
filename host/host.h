//******************************************************************************
// Host Application Header - Message Relay for Enclave Communication
// Copyright (c) 2025, Keystone TEE
//******************************************************************************

#pragma once

#include <cassert>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <memory>
#include <optional>
#include <string>
#include <queue>
#include <mutex>

#include "edge/edge_common.h"
#include "host/keystone.h"
#include "verifier/report.h"

using byte = unsigned char;

// Shared buffer management
class SharedBuffer {
private:
    struct edge_call* const edge_call_;
    uintptr_t const buffer_;
    size_t const buffer_len_;

public:
    SharedBuffer(void* buffer, size_t buffer_len)
        : edge_call_((struct edge_call*)buffer),
          buffer_((uintptr_t)buffer),
          buffer_len_(buffer_len) {}

    uintptr_t ptr() { return buffer_; }

    void set_ok();
    void set_bad_offset();
    void set_bad_ptr();

    int get_ptr_from_offset(edge_data_offset offset, uintptr_t* ptr);
    int args_ptr(uintptr_t* ptr, size_t* size);

    std::optional<std::pair<uintptr_t, size_t>>
    get_call_args_ptr_or_set_bad_offset();

    std::optional<char*> get_c_string_or_set_bad_offset();
    std::optional<unsigned long> get_unsigned_long_or_set_bad_offset();
    std::optional<Report> get_report_or_set_bad_offset();

    uintptr_t data_ptr();
    int validate_ptr(uintptr_t ptr);
    int get_offset_from_ptr(uintptr_t ptr, edge_data_offset* offset);
    int setup_ret(void* ptr, size_t size);
    void setup_ret_or_bad_ptr(unsigned long ret_val);
    int setup_wrapped_ret(void* ptr, size_t size);
    void setup_wrapped_ret_or_bad_ptr(const std::string& ret_val);
};

// Runtime data for enclave execution
struct RunData {
    SharedBuffer shared_buffer;
    std::string nonce;
    std::unique_ptr<Report> report;
};

// Message queue for inter-enclave communication
struct MessageQueue {
    std::queue<std::string> messages;
    std::mutex mutex;
    
    void push(const std::string& msg);
    std::optional<std::string> pop();
    bool empty();
};

// Host application class
class Host {
private:
    std::string eapp_file_;
    std::string rt_file_;
    std::string ld_file_;
    Keystone::Params params_;

    static void dispatch_ocall(RunData& run_data);
    static void print_buffer_wrapper(RunData& run_data);
    static void send_join_request_wrapper(RunData& run_data);
    static void wait_join_request_wrapper(RunData& run_data);
    static void send_challenge_wrapper(RunData& run_data);
    static void get_challenge_wrapper(RunData& run_data);
    static void send_proof_wrapper(RunData& run_data);
    static void wait_proof_wrapper(RunData& run_data);
    static void send_result_wrapper(RunData& run_data);
    static void get_result_wrapper(RunData& run_data);

public:
    void set_eapp_file(const std::string& file) { eapp_file_ = file; }
    void set_rt_file(const std::string& file) { rt_file_ = file; }
    void set_ld_file(const std::string& file) { ld_file_ = file; }
    void set_params(const Keystone::Params& params) { params_ = params; }

    Report run(const std::string& nonce);
};

