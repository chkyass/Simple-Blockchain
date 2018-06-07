#include <iostream>
#include <openssl/rsa.h>
#include <vector>
#include <ctime>
#include "Crypto.hpp"


using namespace std;

struct Receipt {
    string from;
    string to;
    string what;
    string timestamp;
    string b64signature;
};

class User {
    public: 
        User(string name1);
        ~User();
        void generate_receipt(string to, string what);
        void verify_receipt(RSA * pub, Receipt receipt);
        void test();
    private:
        RSA* public = NULL;
        RSA* private = NULL;
        string name;
        vector<Receipt> receiptsV;
        string get_current_time();
};

User::User(string name1) {
    Crypto c;
    name = name1;
    keys = c.generate_keys();
}

User::~User() {
    RSA_free(public);
    RSA_free(private);
}

void User::generate_receipt(string to, string what) {
    Receipt receipt;
    Crypto c;

    receipt.from = name;
    receipt.to = to;
    receipt.what = what;
    receipt.timestamp = get_current_time();
    receipt.b64signature = c.sign_message(keys, to+","+what+","+r.timestamp);
    receiptsV.push_back(r);
}

bool User::verify_receipt(RSA *public, receipt) {
    Crypto c;
    return false;
}

void User::test() {
    /*Crypto c;
    keys = c.generate_keys();
    string signature = c.sign_message(keys,"abcdefgh\naa");
    cout << signature << endl;
    cout << c.verifySignature(keys, "abcdefgh\naaa", signature) <<endl;*/
    cout << get_current_time();
}

string User::get_current_time() {
    time_t rawtime;
    struct tm* timeinfo;
    char buffer[80];
    
    time(&rawtime);
    timeinfo = localtime(&rawtime);

    strftime(buffer, sizeof(buffer), "%d-%m-%Y %I:%M:%S", timeinfo);
    std::string cur_time(buffer);
    
    return cur_time;
}

