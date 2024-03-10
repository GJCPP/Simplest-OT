#pragma once
#define SODIUM_STATIC
#include <iostream>
#include <iomanip>
#include <sodium.h>

namespace ED25519 {
	class curve_point;


	/*
	* This class is a naive encapsulation of the scalar used in the ed25519 curve.
	* It is really just a 256-bit integer under modulo 2^252 + 27742317777372353535851937790883648493.
	* 
	* WARNING: The user is resiponsible for clamping the key if it is to be used as a key, against small sub-group attack.
	*/
	class scalar {
	public:
		friend curve_point;
		friend std::ostream& operator<<(std::ostream& os, const scalar& s);
		scalar() = default;
		scalar(int val);

		void fill_rand();
		void fill_rand_key(); // clamped key.

		scalar operator+(const scalar& other) const;
		scalar operator-(const scalar& other) const;
		scalar operator*(const scalar& other) const;
		scalar operator/(const scalar& other) const;
		
		scalar operator-() const;

		scalar inverse() const;
		scalar clamp() const;

		unsigned char* data();
		const unsigned char* data() const;

	protected:
		unsigned char val[crypto_core_ed25519_UNIFORMBYTES];
	};

	/*
	* WARNING: The operation with scalar will NEVER clamp the input.
	*/
	class curve_point {
	public:
		friend std::ostream& operator<<(std::ostream& os, const curve_point& p);
		curve_point() = default;

		/*
		* \brief Compute base^exp without clamping the key.
		*/
		curve_point(const scalar& exp); 

		void fill_rand();

		curve_point operator+(const curve_point& other) const;
		curve_point operator-(const curve_point& other) const;
		curve_point operator*(const scalar& other) const;

		bool operator==(const curve_point& other) const;

		bool is_on_curve() const;

		unsigned char* data();
		const unsigned char* data() const;
		
		static const size_t BYTE_LENGTH = crypto_core_ed25519_BYTES;
	protected:
		unsigned char val[crypto_core_ed25519_BYTES];
	};
}