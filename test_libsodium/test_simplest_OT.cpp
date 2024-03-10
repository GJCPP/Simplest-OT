#include "test_simplest_OT.h"

bool test_simplest_OT() {
    const size_t msg_len = 12;
    const int choose = 1;
    simplest_OT::sender sender(msg_len);
    simplest_OT::receiver receiver(msg_len);
    simplest_OT::byte_string msg[2] = { (unsigned char*)"012345678910",
        (unsigned char*)"AWESOMEGJCPP" };
    msg[0].resize(msg_len);
    msg[1].resize(msg_len);
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
    std::cout << m.c_str() << std::endl;
    if (m == msg[choose]) {
		return true;
	}
    return false;
}
