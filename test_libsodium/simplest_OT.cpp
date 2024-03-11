#include "simplest_OT.h"

namespace simplest_OT {
	sender::sender(size_t _msg_len)
		: msg_len(_msg_len) {
	}

	void simplest_OT::sender::send_1(ED25519::scalar& _a, ED25519::curve_point& _A) {
		a.fill_rand_key();
		A = ED25519::curve_point(a);

		_a = a;
		_A = A;
	}

	void sender::receive_2(const ED25519::curve_point& _B) {
		B = _B;
	}
	
	void sender::send_3(byte_string& c0, byte_string& c1, const byte_string& m0, const byte_string& m1) {
		if (m0.size() != m1.size()) throw std::runtime_error("simplest_OT: m0 and m1 must have the same length");
		if (m0.size() != msg_len) throw std::runtime_error("simplest_OT: m0 and m1 must have the pre-defined length");
		
		
		c0.resize(msg_len + crypto_secretbox_MACBYTES + crypto_box_NONCEBYTES); // nonce will be paded to the back.
		c1.resize(msg_len + crypto_secretbox_MACBYTES + crypto_box_NONCEBYTES);


		unsigned char key0[crypto_secretbox_KEYBYTES], key1[crypto_secretbox_KEYBYTES] = {};
		unsigned char nonce0[crypto_secretbox_NONCEBYTES], nonce1[crypto_secretbox_NONCEBYTES] = {};
		ED25519::curve_point k0 = B * a, k1 = (B - A) * a;
		//randombytes_buf(nonce0, sizeof nonce0);
		//randombytes_buf(nonce1, sizeof nonce1);

		crypto_generichash(key0, sizeof key0, k0.data(), k0.BYTE_LENGTH, NULL, 0);
		crypto_generichash(key1, sizeof key1, k1.data(), k1.BYTE_LENGTH, NULL, 0);
		crypto_secretbox_easy(&c0[0], m0.data(), m0.size(), nonce0, key0);
		crypto_secretbox_easy(&c1[0], m1.data(), m1.size(), nonce1, key1);
		memcpy(&c0[c0.size() - sizeof nonce0], nonce0, sizeof nonce0);
		memcpy(&c1[c1.size() - sizeof nonce1], nonce1, sizeof nonce1);
	}
	receiver::receiver(size_t _msg_len)
		: msg_len(_msg_len) {
	}
	void receiver::receive_1(const ED25519::curve_point& _A) {
		A = _A;
	}
	void receiver::send_2(int ch, ED25519::curve_point& _B) {
		if (ch != 0 && ch != 1) throw std::runtime_error("simplest_OT: choose must be 0 or 1");
		b.fill_rand_key();
		choose = ch;
		B = choose == 0 ? ED25519::curve_point(b) : A + ED25519::curve_point(b);
		_B = B;
	}
	void receiver::receive_3(const byte_string& c0, const byte_string& c1, byte_string& m) {
		if (c0.size() != c1.size()) throw std::runtime_error("simplest_OT: c0 and c1 must have the same length");
		if (c0.size() != msg_len + crypto_secretbox_MACBYTES + crypto_secretbox_NONCEBYTES)
			throw std::runtime_error("simplest_OT: c0 and c1 must have the pre-defined length");
		
		m.resize(msg_len);

		ED25519::curve_point k = A * b; // g^(ab)
		unsigned char key[crypto_secretbox_KEYBYTES];
		unsigned char nonce[crypto_secretbox_NONCEBYTES];

		crypto_generichash(key, sizeof key, k.data(), ED25519::curve_point::BYTE_LENGTH, NULL, 0); // curve point to key.

		if (choose == 0) {
			memcpy(nonce, &c0[c0.size() - sizeof nonce], sizeof nonce);
			if (crypto_secretbox_open_easy(&m[0], &c0[0], c0.size() - sizeof nonce, nonce, key) != 0) {
				throw std::runtime_error("simplest_OT: decryption failed");
			}
		}
		else {
			memcpy(nonce, &c1[c1.size() - sizeof nonce], sizeof nonce);
			if (crypto_secretbox_open_easy(&m[0], &c1[0], c1.size() - sizeof nonce, nonce, key) != 0) {
				throw std::runtime_error("simplest_OT: decryption failed");
			}
		}
	}
}
