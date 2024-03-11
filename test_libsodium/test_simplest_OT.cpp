#include "test_simplest_OT.h"
#include <random>
bool test_simplest_OT() {
    std::mt19937_64 eng;
    bool fail = false;
    for (int _(0); _ != 100; ++_) {
        size_t msg_len = std::uniform_int<int>(1, 100)(eng);
        int choose = std::uniform_int<int>(0, 1)(eng);
        simplest_OT::sender sender(msg_len);
        simplest_OT::receiver receiver(msg_len);
        simplest_OT::byte_string msg[2];
        msg[0].resize(msg_len);
        msg[1].resize(msg_len);
        randombytes_buf(&msg[0][0], msg_len);
        randombytes_buf(&msg[1][0], msg_len);
        // Sender
        ED25519::scalar a;
        ED25519::curve_point A;
        sender.send_1(a, A);
        // Receiver
        ED25519::curve_point B;
        receiver.receive_1(A);
        receiver.send_2(choose, B);
        // Sender
        simplest_OT::byte_string c0, c1;
        sender.receive_2(B);
        sender.send_3(c0, c1, msg[0], msg[1]);
        // Receiver
        simplest_OT::byte_string m;
        receiver.receive_3(c0, c1, m);
        for (unsigned char c : msg[0])
            std::cout << std::hex << (int)c << " ";
        std::cout << std::endl;
        for (unsigned char c : msg[1])
            std::cout << std::hex << (int)c << " ";
        std::cout << std::endl;
        for (unsigned char c : m)
            std::cout << std::hex << (int)c << " ";
        std::cout << std::endl;
        std::cout << std::endl;
        if (m != msg[choose]) {
            fail = true;
            break;
        }
    }
    if (fail) std::cout << "Faiedl!" << std::endl;
    else std::cout << "Passed." << std::endl;
    return false;
}
