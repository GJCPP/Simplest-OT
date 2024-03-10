#include "ED25519.h"

namespace ED25519
{
	scalar::scalar(int v)
	{
		memset(val, 0, crypto_core_ed25519_UNIFORMBYTES);
		val[0] = v;
	}

	void scalar::fill_rand() 	{
		crypto_core_ed25519_scalar_random(val);
	}
	
	/*
	* \brief Fill the scalar with a random clamped value.
	*/
	void scalar::fill_rand_key() 	{
		crypto_core_ed25519_scalar_random(val);
		val[0] &= 248;
		val[31] &= 127;
		val[31] |= 64;
	}

	scalar scalar::operator+(const scalar& other) const 	{
		scalar result;
		crypto_core_ed25519_scalar_add(result.val, val, other.val);
		return result;
	}
	scalar scalar::operator-(const scalar& other) const 	{
		scalar result;
		crypto_core_ed25519_scalar_sub(result.val, val, other.val);
		return result;
	}
	scalar scalar::operator*(const scalar& other) const	{
		scalar result;
		crypto_core_ed25519_scalar_mul(result.val, val, other.val);
		return result;
	}
	scalar scalar::operator/(const scalar& other) const	{
		scalar result = other.inverse();
		crypto_core_ed25519_scalar_mul(result.val, val, result.val);
		return result;
	}
	scalar scalar::operator-() const {
		scalar result;
		crypto_core_ed25519_scalar_negate(result.val, val);
		return result;
	}
	scalar scalar::inverse() const {
		scalar result;
		crypto_core_ed25519_scalar_invert(result.val, val);
		return result;
	}
	scalar scalar::clamp() const {
		scalar result = *this;
		result.val[0] &= 248;
		result.val[31] &= 127;
		result.val[31] |= 64;
		return result;
	}
	unsigned char* scalar::data() {
		return val;
	}
	const unsigned char* scalar::data() const {
		return val;
	}
	std::ostream& operator<<(std::ostream& os, const scalar& s)	{
		os << std::hex << std::setw(2) << std::setfill('0') << (int)s.val[0];
		for (int i = 1; i < 32; i++) {
			os << " " << std::hex << std::setw(2) << std::setfill('0') << (int)s.val[i];
		}
		return os;
	}
	std::ostream& operator<<(std::ostream& os, const curve_point& p) {
		os << std::hex << std::setw(2) << std::setfill('0') << (int)p.val[0];
		for (int i = 1; i < 32; i++) {
			os << " " << std::hex << std::setw(2) << std::setfill('0') << (int)p.val[i];
		}
		return os;
	}
	curve_point::curve_point(const scalar& key) {
		crypto_scalarmult_ed25519_base_noclamp(val, key.val);
	}
	void curve_point::fill_rand() {
		crypto_core_ed25519_scalar_random(val);
		crypto_scalarmult_ed25519_base_noclamp(val, val);
	}
	curve_point curve_point::operator+(const curve_point& other) const {
		curve_point result;
		crypto_core_ed25519_add(result.val, val, other.val);
		return result;
	}
	curve_point curve_point::operator-(const curve_point& other) const {
		curve_point result;
		crypto_core_ed25519_sub(result.val, val, other.val);
		return result;
	}
	curve_point curve_point::operator*(const scalar& other) const {
		curve_point result;
		crypto_scalarmult_ed25519_noclamp(result.val, other.val, val);
		return result;
	}
	bool curve_point::operator==(const curve_point& other) const {
		return memcmp(val, other.val, crypto_core_ed25519_BYTES) == 0;
	}
	bool curve_point::is_on_curve() const {
		return crypto_core_ed25519_is_valid_point(val) == 0;
	}
	unsigned char* curve_point::data() {
		return val;
	}
	const unsigned char* curve_point::data() const {
		return val;
	}
}
