#include <stdio.h>
#include <string.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bio.h>

#include <iostream>
#include <vector>

using namespace std;

class Crypto {
    public:
        string sign_message(RSA* keys, string message);
        void write_RSA_to_File(RSA* rsa, string privFilename, string pubFilename);
        bool verifySignature(RSA* keys, string plainText, string signature);
        RSA* generate_keys();
    private:
        int seed_prng();
        size_t calcDecodeLength(const char* b64input);
        bool RSA_sign(RSA* rsa, const unsigned char* msg, size_t msglen, unsigned char** encmsg, size_t* encmsglen);
        void base64_encode(const unsigned char* buffer, size_t length, char** base64Text);
        void Base64Decode(char* b64message, unsigned char** decoded, size_t* length);
        bool RSAVerifySignature(RSA* rsa, unsigned char* MsgHash, size_t MsgHashLen, const char* Msg, size_t MsgLen);
};

int Crypto::seed_prng() {
    return RAND_load_file("/dev/urandom", 2048);
}

RSA* Crypto::split_keys() {
    RSA* public = RSA_new();
    
}

RSA* Crypto::generate_keys() {
    if(seed_prng() < 0) {
        cout << "PRNG seed error" << endl;
        return NULL;
    }
    
    BIGNUM* bne = BN_new();
    unsigned long e = RSA_F4;
    if(!BN_set_word(bne, e)) {
        cout << "BN error" << endl;
        BN_free(bne);
        return NULL;
    }

    RSA* keypair = RSA_new();
    if(!RSA_generate_key_ex(keypair, 2048, bne, NULL)){
        cout << "RSA error" << endl;
        RSA_free(keypair);
        return NULL;
    }
    BN_free(bne);
    return keypair;
}


void Crypto::write_RSA_to_File(RSA* rsa, string privFilename, string pubFilename) {
    BIO* bp_public = BIO_new_file(pubFilename.c_str(), "w+");
    PEM_write_bio_RSAPublicKey(bp_public, rsa);

    BIO* bp_private = BIO_new_file(privFilename.c_str(), "w+");
    PEM_write_bio_RSAPrivateKey(bp_private, rsa, NULL, NULL, 0, NULL, NULL);
}

bool Crypto::RSA_sign(RSA* rsa,
            const unsigned char* msg, 
            size_t msglen, 
            unsigned char** encmsg, 
            size_t* encmsglen) {

    // Create EVP context for MD=RSA            
    EVP_MD_CTX* RSASignCtx = EVP_MD_CTX_create();
    // Store private key in EVP_PKEY
    EVP_PKEY* priKey  = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(priKey, rsa);

    if (EVP_DigestSignInit(RSASignCtx,NULL, EVP_sha256(), NULL,priKey)<=0) {
        return false;
    }

    // Hash Msglen of data from Msg to the context 
    if (EVP_DigestSignUpdate(RSASignCtx, msg, msglen) <= 0) {
        return false;
    }

    // Compute and store the signature length in MsgLenEnc
    if (EVP_DigestSignFinal(RSASignCtx, NULL, encmsglen) <=0) {
        return false;
    }
    *encmsg = (unsigned char*)malloc(*encmsglen);

    //Store the signature in EncMsg
    if (EVP_DigestSignFinal(RSASignCtx, *encmsg, encmsglen) <= 0) {
        return false;
    }

    EVP_MD_CTX_cleanup(RSASignCtx);
    return true;
}

void Crypto::base64_encode( const unsigned char* buffer, 
                   size_t length, 
                   char** base64Text) { 
    BIO *bio, *b64;
    BUF_MEM *bufferPtr;
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    
    //push actions. bas64encode and write to biomemory
    bio = BIO_push(b64, bio);

    //Write length data from buffer passing throw the chain
    BIO_write(bio, buffer, length);
    BIO_flush(bio);

    BIO_get_mem_ptr(bio, &bufferPtr);
    BIO_set_close(bio, BIO_NOCLOSE);
    BIO_free_all(bio);
    *base64Text=(*bufferPtr).data;
}

string Crypto::sign_message(RSA* keys, string message) {
    unsigned char* encMessage;
    char* base64Text;
    size_t encMessageLength;
    RSA_sign(keys, (unsigned char*) message.c_str(), message.length(), &encMessage, &encMessageLength);
    base64_encode(encMessage, encMessageLength, &base64Text);
    free(encMessage);
    string signature(base64Text);
    free(base64Text);
    return signature;
}

size_t Crypto::calcDecodeLength(const char* b64input) {
    size_t len = strlen(b64input);
    size_t padding = 0;
    if (b64input[len-1] == '=' && b64input[len-2] == '=') //last two chars are =
        padding = 2;
    else if (b64input[len-1] == '=') //last char is =
        padding = 1;
    return (len*3)/4 - padding;
}

void Crypto::Base64Decode(char* b64message, unsigned char** decoded, size_t* length) {
    BIO *bio, *b64;
    int decodeLen = calcDecodeLength(b64message);
    *decoded = (unsigned char*)malloc(decodeLen + 1);
    (*decoded)[decodeLen] = '\0';

    // -1 implie that the string is null terminated
    bio = BIO_new_mem_buf(b64message, -1);
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);

    // travel through the chain from the end in a case of read
    *length = BIO_read(bio, *decoded, strlen(b64message));
    BIO_free_all(bio);
}

bool Crypto::RSAVerifySignature( RSA* rsa, 
                         unsigned char* MsgHash, 
                         size_t MsgHashLen, 
                         const char* Msg, 
                         size_t MsgLen) {
    EVP_PKEY* pubKey  = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(pubKey, rsa);
    EVP_MD_CTX* m_RSAVerifyCtx = EVP_MD_CTX_create();
    if (EVP_DigestVerifyInit(m_RSAVerifyCtx,NULL, EVP_sha256(),NULL,pubKey)<=0) {
        return false;
    }
    if (EVP_DigestVerifyUpdate(m_RSAVerifyCtx, Msg, MsgLen) <= 0) {
        return false;
    }
    
    if (EVP_DigestVerifyFinal(m_RSAVerifyCtx, MsgHash, MsgHashLen)==1) {
        EVP_MD_CTX_cleanup(m_RSAVerifyCtx);
        return true;
    }
    
    EVP_MD_CTX_cleanup(m_RSAVerifyCtx);
    return false;
    
}

bool Crypto::verifySignature(RSA* keys, string plainText, string signature) {
    char* signatureBase64 = (char*) signature.c_str();
    unsigned char* encMessage;
    size_t encMessageLength;
    bool authentic;
    Base64Decode(signatureBase64, &encMessage, &encMessageLength);
    authentic = RSAVerifySignature(keys, encMessage, encMessageLength, plainText.c_str(), plainText.length());
    free(encMessage);
    return authentic;
}