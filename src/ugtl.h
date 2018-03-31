#pragma once

namespace gtl {

template<typename F>
struct final_action {
    F act;
    final_action(final_action&&) = default;
    ~final_action() { act(); }
};

template<typename F>
final_action<F> finally(F&& act)
{
    return { std::forward<F>(act) };
}

}
