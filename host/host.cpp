//******************************************************************************
// Host Application Implementation - Pure Message Relay
// Copyright (c) 2025, Keystone TEE
//******************************************************************************

#include "host.h"

#include <getopt.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctime>
#include <cstdlib>
#include <cerrno>
#include <cstdio>
#include <functional>
#include <iostream>
#include <stdexcept>
#include <string>
#include <thread>
#include <chrono>

#include "edge/edge_common.h"
#include "edge/edge_call.h"
#include "edge/edge_syscall.h"
#include "host/keystone.h"
#include "verifier/report.h"

// OCALL definitions
#define OCALL_PRINT_BUFFER         1
#define OCALL_SEND_JOIN_REQUEST    2
#define OCALL_WAIT_JOIN_REQUEST    3
#define OCALL_SEND_CHALLENGE       4
#define OCALL_GET_CHALLENGE        5
#define OCALL_SEND_PROOF           6
#define OCALL_WAIT_PROOF           7
#define OCALL_SEND_RESULT          8
#define OCALL_GET_RESULT           9

// ============================================================================
// Global message queues for inter-enclave communication
// ============================================================================
static MessageQueue join_request_queue;
static MessageQueue challenge_queue;
static MessageQueue proof_queue;
static MessageQueue result_queue;

// ============================================================================
// MessageQueue implementation
// ============================================================================
void MessageQueue::push(const std::string& msg) {
    std::lock_guard<std::mutex> lock(mutex);
    messages.push(msg);
}

std::optional<std::string> MessageQueue::pop() {
    std::lock_guard<std::mutex> lock(mutex);
    if (messages.empty()) {
        return std::nullopt;
    }
    std::string msg = messages.front();
    messages.pop();
    return msg;
}

bool MessageQueue::empty() {
    std::lock_guard<std::mutex> lock(mutex);
    return messages.empty();
}

// ============================================================================
// SharedBuffer implementation
// ============================================================================
void SharedBuffer::set_ok() {
    edge_call_->return_data.call_status = CALL_STATUS_OK;
}

void SharedBuffer::set_bad_offset() {
    edge_call_->return_data.call_status = CALL_STATUS_BAD_OFFSET;
}

void SharedBuffer::set_bad_ptr() {
    edge_call_->return_data.call_status = CALL_STATUS_BAD_PTR;
}

int SharedBuffer::get_ptr_from_offset(edge_data_offset offset, uintptr_t* ptr) {
    if (offset > UINTPTR_MAX - buffer_ || offset > buffer_len_) {
        return -1;
    }
    *ptr = buffer_ + offset;
    return 0;
}

int SharedBuffer::args_ptr(uintptr_t* ptr, size_t* size) {
    *size = edge_call_->call_arg_size;
    return get_ptr_from_offset(edge_call_->call_arg_offset, ptr);
}

std::optional<std::pair<uintptr_t, size_t>>
SharedBuffer::get_call_args_ptr_or_set_bad_offset() {
    uintptr_t call_args;
    size_t arg_len;
    if (args_ptr(&call_args, &arg_len) != 0) {
        set_bad_offset();
        return std::nullopt;
    }
    return std::pair{call_args, arg_len};
}

std::optional<char*> SharedBuffer::get_c_string_or_set_bad_offset() {
    auto v = get_call_args_ptr_or_set_bad_offset();
    return v.has_value() ? std::optional{(char*)v.value().first} : std::nullopt;
}

std::optional<unsigned long> SharedBuffer::get_unsigned_long_or_set_bad_offset() {
    auto v = get_call_args_ptr_or_set_bad_offset();
    return v.has_value() ? std::optional{*(unsigned long*)v.value().first}
                         : std::nullopt;
}

std::optional<Report> SharedBuffer::get_report_or_set_bad_offset() {
    auto v = get_call_args_ptr_or_set_bad_offset();
    if (!v.has_value()) return std::nullopt;
    Report ret;
    ret.fromBytes((byte*)v.value().first);
    return ret;
}

uintptr_t SharedBuffer::data_ptr() {
    return (uintptr_t)edge_call_ + sizeof(struct edge_call);
}

int SharedBuffer::validate_ptr(uintptr_t ptr) {
    if (ptr > buffer_ + buffer_len_ || ptr < buffer_) {
        return 1;
    }
    return 0;
}

int SharedBuffer::get_offset_from_ptr(uintptr_t ptr, edge_data_offset* offset) {
    int valid = validate_ptr(ptr);
    if (valid != 0) return valid;
    *offset = ptr - buffer_;
    return 0;
}

int SharedBuffer::setup_ret(void* ptr, size_t size) {
    edge_call_->return_data.call_ret_size = size;
    return get_offset_from_ptr(
        (uintptr_t)ptr, &edge_call_->return_data.call_ret_offset);
}

void SharedBuffer::setup_ret_or_bad_ptr(unsigned long ret_val) {
    uintptr_t data_section = data_ptr();
    memcpy((void*)data_section, &ret_val, sizeof(unsigned long));

    if (setup_ret((void*)data_section, sizeof(unsigned long))) {
        set_bad_ptr();
    } else {
        set_ok();
    }
}

int SharedBuffer::setup_wrapped_ret(void* ptr, size_t size) {
    struct edge_data data_wrapper;
    data_wrapper.size = size;
    get_offset_from_ptr(
        buffer_ + sizeof(struct edge_call) + sizeof(struct edge_data),
        &data_wrapper.offset);

    memcpy(
        (void*)(buffer_ + sizeof(struct edge_call) + sizeof(struct edge_data)),
        ptr, size);

    memcpy(
        (void*)(buffer_ + sizeof(struct edge_call)), &data_wrapper,
        sizeof(struct edge_data));

    edge_call_->return_data.call_ret_size = sizeof(struct edge_data);
    return get_offset_from_ptr(
        buffer_ + sizeof(struct edge_call),
        &edge_call_->return_data.call_ret_offset);
}

void SharedBuffer::setup_wrapped_ret_or_bad_ptr(const std::string& ret_val) {
    if (setup_wrapped_ret((void*)ret_val.c_str(), ret_val.length() + 1)) {
        set_bad_ptr();
    } else {
        set_ok();
    }
    return;
}

// ============================================================================
// OCALL Wrappers - Pure message forwarding
// ============================================================================

void Host::print_buffer_wrapper(RunData& run_data) {
    SharedBuffer& shared_buffer = run_data.shared_buffer;
    auto t = shared_buffer.get_c_string_or_set_bad_offset();
    if (t.has_value()) {
        printf("%s", t.value());
        fflush(stdout);
        auto ret_val = strlen(t.value());
        shared_buffer.setup_ret_or_bad_ptr(ret_val);
    }
}

void Host::send_join_request_wrapper(RunData& run_data) {
    SharedBuffer& shared_buffer = run_data.shared_buffer;
    
    auto args = shared_buffer.get_call_args_ptr_or_set_bad_offset();
    if (args.has_value()) {
        std::string msg((char*)args.value().first, args.value().second);
        
        printf("[Host] 📤 Forwarding join request (%zu bytes)\n", msg.size());
        join_request_queue.push(msg);
        
        shared_buffer.set_ok();
    }
}

void Host::wait_join_request_wrapper(RunData& run_data) {
    SharedBuffer& shared_buffer = run_data.shared_buffer;
    
    printf("[Host] 📥 Waiting for join request...\n");
    
    // Wait for message
    while (join_request_queue.empty()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    
    auto msg = join_request_queue.pop();
    if (msg.has_value()) {
        printf("[Host] 📬 Got join request (%zu bytes)\n", msg.value().size());
        shared_buffer.setup_wrapped_ret((void*)msg.value().c_str(), 
                                        msg.value().size());
    } else {
        shared_buffer.setup_ret_or_bad_ptr(0);
    }
}

void Host::send_challenge_wrapper(RunData& run_data) {
    SharedBuffer& shared_buffer = run_data.shared_buffer;
    
    auto args = shared_buffer.get_call_args_ptr_or_set_bad_offset();
    if (args.has_value()) {
        std::string msg((char*)args.value().first, args.value().second);
        
        uint64_t nonce = *(uint64_t*)args.value().first;
        printf("[Host] 📤 Forwarding challenge (nonce: %lu)\n", nonce);
        
        challenge_queue.push(msg);
        shared_buffer.set_ok();
    }
}

void Host::get_challenge_wrapper(RunData& run_data) {
    SharedBuffer& shared_buffer = run_data.shared_buffer;
    
    printf("[Host] 📥 Waiting for challenge...\n");
    
    // Wait for challenge
    while (challenge_queue.empty()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    
    auto msg = challenge_queue.pop();
    if (msg.has_value()) {
        uint64_t nonce = *(uint64_t*)msg.value().c_str();
        printf("[Host] 📬 Got challenge (nonce: %lu)\n", nonce);
        
        shared_buffer.setup_wrapped_ret((void*)msg.value().c_str(), 
                                        msg.value().size());
    } else {
        shared_buffer.setup_ret_or_bad_ptr(0);
    }
}

void Host::send_proof_wrapper(RunData& run_data) {
    SharedBuffer& shared_buffer = run_data.shared_buffer;
    
    auto args = shared_buffer.get_call_args_ptr_or_set_bad_offset();
    if (args.has_value()) {
        std::string msg((char*)args.value().first, args.value().second);
        
        printf("[Host] 📤 Forwarding proof (%zu bytes)\n", msg.size());
        proof_queue.push(msg);
        
        shared_buffer.set_ok();
    }
}

void Host::wait_proof_wrapper(RunData& run_data) {
    SharedBuffer& shared_buffer = run_data.shared_buffer;
    
    printf("[Host] 📥 Waiting for proof...\n");
    
    // Wait for proof
    while (proof_queue.empty()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    
    auto msg = proof_queue.pop();
    if (msg.has_value()) {
        printf("[Host] 📬 Got proof (%zu bytes)\n", msg.value().size());
        shared_buffer.setup_wrapped_ret((void*)msg.value().c_str(), 
                                        msg.value().size());
    } else {
        shared_buffer.setup_ret_or_bad_ptr(0);
    }
}

void Host::send_result_wrapper(RunData& run_data) {
    SharedBuffer& shared_buffer = run_data.shared_buffer;
    
    auto args = shared_buffer.get_call_args_ptr_or_set_bad_offset();
    if (args.has_value()) {
        std::string msg((char*)args.value().first, args.value().second);
        
        printf("[Host] 📤 Forwarding result: %s\n", msg.c_str());
        result_queue.push(msg);
        
        shared_buffer.set_ok();
    }
}

void Host::get_result_wrapper(RunData& run_data) {
    SharedBuffer& shared_buffer = run_data.shared_buffer;
    
    printf("[Host] 📥 Waiting for result...\n");
    
    // Wait for result
    while (result_queue.empty()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    
    auto msg = result_queue.pop();
    if (msg.has_value()) {
        printf("[Host] 📬 Got result: %s\n", msg.value().c_str());
        shared_buffer.setup_wrapped_ret((void*)msg.value().c_str(), 
                                        msg.value().size());
    } else {
        shared_buffer.setup_ret_or_bad_ptr(0);
    }
}

// ============================================================================
// OCALL Dispatcher
// ============================================================================
void Host::dispatch_ocall(RunData& run_data) {
    struct edge_call* edge_call = (struct edge_call*)run_data.shared_buffer.ptr();
    
    // Handle syscalls (from Rust std library operations)
    if (edge_call->call_id == EDGECALL_SYSCALL) {
        incoming_syscall(edge_call);
        return;
    }
    
    switch (edge_call->call_id) {
        case OCALL_PRINT_BUFFER:
            print_buffer_wrapper(run_data);
            break;
        case OCALL_SEND_JOIN_REQUEST:
            send_join_request_wrapper(run_data);
            break;
        case OCALL_WAIT_JOIN_REQUEST:
            wait_join_request_wrapper(run_data);
            break;
        case OCALL_SEND_CHALLENGE:
            send_challenge_wrapper(run_data);
            break;
        case OCALL_GET_CHALLENGE:
            get_challenge_wrapper(run_data);
            break;
        case OCALL_SEND_PROOF:
            send_proof_wrapper(run_data);
            break;
        case OCALL_WAIT_PROOF:
            wait_proof_wrapper(run_data);
            break;
        case OCALL_SEND_RESULT:
            send_result_wrapper(run_data);
            break;
        case OCALL_GET_RESULT:
            get_result_wrapper(run_data);
            break;
        default:
            printf("[Host] Unknown OCALL: %lu\n", edge_call->call_id);
            break;
    }
}

// ============================================================================
// Host::run - Execute enclave
// ============================================================================
Report Host::run(const std::string& nonce) {
    printf("=== Starting Enclave: %s ===\n", eapp_file_.c_str());
    
    Keystone::Enclave enclave;
    enclave.init(eapp_file_.c_str(), rt_file_.c_str(), ld_file_.c_str(), params_);

    RunData run_data{
        SharedBuffer{enclave.getSharedBuffer(), enclave.getSharedBufferSize()},
        nonce, nullptr};

    enclave.registerOcallDispatch([&run_data](void* buffer) {
        assert(buffer == (void*)run_data.shared_buffer.ptr());
        dispatch_ocall(run_data);
    });

    edge_call_init_internals(
        (uintptr_t)enclave.getSharedBuffer(), enclave.getSharedBufferSize());

    printf("=== Enclave running ===\n");
    uintptr_t encl_ret;
    enclave.run(&encl_ret);

    if (run_data.report != nullptr) {
        printf("=== Enclave completed successfully ===\n");
        return *run_data.report;
    } else {
        printf("=== Enclave completed (no report) ===\n");
        Report dummy_report;
        return dummy_report;
    }
}

// ============================================================================
// Main function
// ============================================================================
int main(int argc, char** argv) {
    if (argc < 4) {
        printf("Usage: %s <prover_eapp> <verifier_eapp> <runtime> <loader>\n", argv[0]);
        printf("Example: %s enclave1 enclave2 eyrie-rt loader.bin\n", argv[0]);
        return 1;
    }
    
    srand(time(nullptr));
    
    std::string prover_eapp = argv[1];
    std::string verifier_eapp = argv[2];
    std::string runtime = argv[3];
    std::string loader = argv[4];
    
    Keystone::Params params;
    params.setFreeMemSize(8 * 1024 * 1024);   // 8MB
    params.setUntrustedSize(2 * 1024 * 1024); // 2MB
    
    std::string nonce = "zkacl_test_" + std::to_string(time(nullptr));
    
    printf("\n");
    printf("╔═══════════════════════════════════════════════════════════╗\n");
    printf("║     ZK-ACL Identity Authentication for Keystone TEE      ║\n");
    printf("╚═══════════════════════════════════════════════════════════╝\n");
    printf("\n");
    printf("Configuration:\n");
    printf("  - Prover:   %s\n", prover_eapp.c_str());
    printf("  - Verifier: %s\n", verifier_eapp.c_str());
    printf("  - Runtime:  %s\n", runtime.c_str());
    printf("  - Nonce:    %s\n", nonce.c_str());
    printf("\n");
    
    // Run verifier in separate thread
    printf("═══ Starting Verifier (Enclave2) ═══\n\n");
    
    Host verifier_host;
    verifier_host.set_eapp_file(verifier_eapp);
    verifier_host.set_rt_file(runtime);
    verifier_host.set_ld_file(loader);
    verifier_host.set_params(params);
    
    std::thread verifier_thread([&]() {
        try {
            verifier_host.run(nonce);
        } catch (const std::exception& e) {
            printf("Verifier error: %s\n", e.what());
        }
    });
    
    // Give verifier time to start
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    
    // Run prover
    printf("\n═══ Starting Prover (Enclave1) ═══\n\n");
    
    Host prover_host;
    prover_host.set_eapp_file(prover_eapp);
    prover_host.set_rt_file(runtime);
    prover_host.set_ld_file(loader);
    prover_host.set_params(params);
    
    try {
        prover_host.run(nonce);
    } catch (const std::exception& e) {
        printf("Prover error: %s\n", e.what());
        return 1;
    }
    
    // Wait for verifier to complete
    verifier_thread.join();
    
    printf("\n");
    printf("╔═══════════════════════════════════════════════════════════╗\n");
    printf("║            Test Completed Successfully                   ║\n");
    printf("╚═══════════════════════════════════════════════════════════╝\n");
    printf("\n");
    
    return 0;
}

