#pragma once

#include <net/buf.h>

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

struct autounref {
	autounref(struct net_buf *buf) : buf_{buf} {}
	~autounref() {
		if (buf_ != nullptr) {
			net_buf_unref(buf_);
			buf_ = nullptr;
		}
	}

private:
	struct net_buf* buf_;
};
