#ifndef _AP4_DECRYPT_H_
#define _AP4_DECRYPT_H_

#include <cstdint>
#include <cstdlib>

class AP4_Decrypt {
public:
	AP4_Decrypt() = delete;
	~AP4_Decrypt() = delete;
	AP4_Decrypt(const AP4_Decrypt& other) = delete;
	AP4_Decrypt& operator=(const AP4_Decrypt& other) = delete;
	AP4_Decrypt(AP4_Decrypt&& other) = delete;
	AP4_Decrypt& operator=(AP4_Decrypt&& other) = delete;

	static void decrypt(block_t** fragment, const char* keyId, const char* key);
	static void split(block_t** fragment, uint8_t** initData, size_t& initSize);
	static void split(block_t** fragment);

private:
	void* operator new(size_t);
	void* operator new(size_t, void*);
	void* operator new[](size_t);
	void* operator new[](size_t, void*);
};

#endif // !_AP4_DECRYPT_H_
