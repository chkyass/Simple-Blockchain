#include "User.hpp"
#include <vector>

int main() {
    string s_acc[] = {"Blue", "Red"};
    vector<string> v_account(s_acc, s_acc+2);
    User u("Alice");
    u.test();
}