#pragma once

namespace std {

template<class InputIt, class OutputIt>
OutputIt copy(InputIt first, InputIt last,
              OutputIt d_first)
{
    while (first != last) {
        *d_first++ = *first++;
    }
    return d_first;
}


}

template <typename F>
struct scopeguard {
	scopeguard(F f) : f_(f) {}
	~scopeguard() { f_(); }

private:
	F f_;
};

template <typename F>
scopeguard<F> make_guard(F f) {
	return scopeguard<F>(f);
};
