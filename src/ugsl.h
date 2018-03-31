/*
 * Copyright (c) 2018 Google LLC.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <utility>

namespace gsl
{

template <typename T> struct span {
	template <std::size_t N> span(T (&arr)[N]) : p_(&arr[0]), size_(N) {}
	template <typename U> span(U &t) : p_(t.begin()), size_(t.size()) {}

	span(T *p, size_t size) : p_(p), size_(size) {}

	T *begin() { return p_; }
	T *end() { return p_ + size_; }
	const T *cbegin() const { return p_; }
	const T *cend() const { return p_ + size_; }
	const T *data() const { return p_; }
	size_t size() const { return size_; }
	bool empty() const { return p_ == nullptr || size_ <= 0; }
	T at(size_t off) const
	{
		if (empty()) {
			return 0;
		}
		return p_[off];
	}
	template <typename U> span<U> cast() const
	{
		return {(U *)p_, size_ * sizeof(T) / sizeof(U)};
	}
	const span<T> subspan(size_t off, size_t size) const {
		if (off + size > size_) {
			return {};
		}
		return {p_ + off, size};
	}

      protected:
		span() : p_{nullptr}, size_{0} {}

	T *p_;
	size_t size_;
};

template <typename F> struct final_action {
	F act;
	final_action(final_action &&) = default;
	~final_action() { act(); }
};

template <typename F> final_action<F> finally(F &&act)
{
	return {std::forward<F>(act)};
}

}
