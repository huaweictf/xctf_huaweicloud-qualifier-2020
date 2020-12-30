#include <iostream>
#include <array>
#include <memory>
#include <cstdint>
#include <unistd.h>
using namespace std;

constexpr size_t NUM_NOTES = 0x100;
constexpr size_t SIZE = 8;
array<unique_ptr<char[]>, NUM_NOTES> notes;

bool read_input(char* buf, size_t len)
{
	if (len == 0) return true;
	size_t i;
	for (i = 0; i < len - 1; i++)
	{
		ssize_t ret = read(STDIN_FILENO, buf + i, 1);
		if (ret != 1)
			exit(-1);
		if (buf[i] == '\n')
			break;
	}
	buf[i] = 0;
	return i == len - 1;
}

inline unique_ptr<char[]> get_idx(size_t idx)
{
	return move(notes[idx]);
}

int main()
{
	setvbuf(stdin, nullptr, 2, 0);
	setvbuf(stdout, nullptr, 2, 0);
	setvbuf(stderr, nullptr, 2, 0);

	size_t tmp = 0;
	while (true)
	{
	cout << "> ";
	tmp = 1337;
	cin >> tmp;
	switch (tmp)
	{
		case 0:
		{
			auto buf = make_unique<char[]>(SIZE);
			cout << "> ";
			read_input(buf.get(), SIZE);
			cout << "> ";
			cin >> tmp;
			if (tmp >= NUM_NOTES)
				break;
			notes[tmp] = move(buf);
		}
		break;
		case 1:
		{
			cout << "> ";
			cin >> tmp;
			if (tmp >= NUM_NOTES)
				break;
			auto p = get_idx(tmp).get();
			if (p == nullptr)
				break;
			puts(p);
			cout << "> ";
			read_input(p, SIZE);
		}
		break;
		default:
		return 0;
	}
	}
	return 0;
}
//g++ -s -O1 -std=c++14 main.cpp -o chall