#pragma once
#include <string>
#define SODIUM_STATIC
#include "ED25519.h"


namespace simplest_OT{
	/*
	*	@inproceedings{chou2015simplest,
			title={The simplest protocol for oblivious transfer},
			author={Chou, Tung and Orlandi, Claudio},
			booktitle={Progress in Cryptology--LATINCRYPT 2015: 4th International Conference on Cryptology and Information Security in Latin America, Guadalajara, Mexico, August 23-26, 2015, Proceedings 4},
			pages={40--58},
			year={2015},
			organization={Springer}
		}

		This is the implementation of the simplest OT protocol in the paper above.
		It is a 2-OUT-OF-1 OT.


		Suppose the generator of the group is g, the sender has a message m0 and m1, the receiver has a bit b.
		Let the sender be at left side, the receiver at right.



		The sender picks a random a
		                                       A = g^a
		                            ---------------------------->
									                                  The receiver has a bit c.
									                                  The receiver picks B = c==0 ? g^b : g^b * A
		                                          B
                                    <----------------------------
		The sender let k_0 = B^a, k_1 = (B/A)^a
		Whis is k_0 = c==0? g^(ab) : g^(ab+aa)
		        k_1 = c==0? g^(ab-aa) : g^(ab)
				                     Enc(k_0, m_0), Enc(k_1, m_1)
				                    ---------------------------->
									                                  The receiver decrypts the message with k_c=g^(ab).

		Well, now getting enough of the "object-oriented" programming, I will just use the C style.
		The communication is left for caller to implement.
		You will see it soon :)
	*/
	typedef std::basic_string<unsigned char> byte_string;
	class sender {
	public:

		sender(size_t _msg_len);

		void send_1(ED25519::scalar& a, ED25519::curve_point& A);

		void receive_2(const ED25519::curve_point& B);

		void send_3(byte_string& c0, byte_string& c1, const byte_string& m0, const byte_string& m1);

	protected:
		int msg_len;
		ED25519::scalar a = {};
		ED25519::curve_point A = {}, B = {};
	};

	class receiver {
	public:
		receiver(size_t _msg_len);

		void receive_1(const ED25519::curve_point& A);

		void send_2(int choose, ED25519::curve_point& B);

		void receive_3(const byte_string& c0, const byte_string& c1, byte_string& m);

	protected:
		int choose;
		int msg_len;
		ED25519::scalar b;
		ED25519::curve_point A, B;
		byte_string c0, c1;
	};
}

