//
// Created by topalc on 19.06.2020.
//

#ifndef CRYPT_PRJ3_TLS_USER_H
#define CRYPT_PRJ3_TLS_USER_H

#endif //CRYPT_PRJ3_TLS_USER_H

#include <string>
#include <iostream>
#include <cstdio>
#include <cmath>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/aes.h>
#include <openssl/objects.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <vector>
#include <openssl/cmac.h>
#include <time.h>

using namespace std;


class USER
{
private:
    BIGNUM *x, *secret_encryptkey, *secret_MACkey;  //x means x or y in the diffie hellman
    BN_CTX *ctx;                                    //used internally by the bignum lib
    clock_t start, end;                             //used for the performance metrics

public:
    BIGNUM* rx_msg, *shared_sec, *p , *g;
    string user_name;

    USER(string name, BIGNUM *p_in, BIGNUM *g_in){

        user_name = name;
        x = BN_new();
        p = BN_new();
        g = BN_new();
        shared_sec = BN_new();

        p = p_in;       //cyclic group
        g = g_in;       //generator

        secret_encryptkey = BN_new();   //will be derived from shared secret
        secret_MACkey = BN_new();       //will be derived from shared secret

        BN_generate_prime_ex(x,128,0,NULL,NULL,NULL);   //randomly generated prime number for diffie-hellman protocol

        printf(" (X or Y):\t");
        BN_print_fp(stdout, x);
        printf("\n");
    }


    bool generate_key();                                                  //generates RSA-512 keys for digital signature
    BIGNUM* ping_tx();
    void ping_rx(BIGNUM* incoming_msg);
    BIGNUM* pong_tx();
    void pong_rx(string name,BIGNUM* incoming_msg);
    void derive_keys();                                                             //uses SHA-1
    BIGNUM *digital_signature(BIGNUM* sign_content);                               //uses RSA-512 inside
    bool check_digsign(string name, BIGNUM* plaintext, BIGNUM* ciphertext);
    BIGNUM *encrypt(BIGNUM* plaintext);                                           // AES-CBC ENCRYPT
    BIGNUM *decrypt(BIGNUM* ciphertext);                                         // AES-CBC DECRYPT
    BIGNUM *MAC(BIGNUM* message_bd);                                            // CBC-MAC
    bool check_MAC(BIGNUM* incoming_data, BIGNUM* incoming_MAC);
    BIGNUM* txFirstData(string data_in);
    void rxFirstData(string name, BIGNUM* incoming_data);
    BIGNUM* txData(string data_in);
    void rxData(BIGNUM* incoming_msg);
};


bool USER::generate_key()
{

    /* Recording the starting clock tick.*/
    start = clock();

    int				ret = 0;
    RSA				*r = RSA_new();
    BIGNUM			*bne = NULL;
    BIO				*bp_public = NULL, *bp_private = NULL;
    string          temp;



    int				bits = 512;
    //  unsigned long	e = RSA_F4;

    // 1. generate rsa key
    bne = BN_new();
    ret = BN_set_word(bne,RSA_F4);
    if(ret != 1){
        goto free_all;
    }
//    ret =
    if(!RSA_generate_key_ex(r, bits, bne, NULL)){
        goto free_all;
    }

    // 2. save public key
    temp = user_name;
    bp_public = BIO_new_file(temp.append("_public.pem").c_str() , "w+");
    if(!PEM_write_bio_RSAPublicKey(bp_public, r)){
        goto free_all;
    }

    // 3. save private key
    temp = user_name;
    bp_private = BIO_new_file(temp.append("_private.pem").c_str(), "w+");
    ret = PEM_write_bio_RSAPrivateKey(bp_private, r, NULL, NULL, 0, NULL, NULL);

    // 4. free
    free_all:

    BIO_free_all(bp_public);
    BIO_free_all(bp_private);
    RSA_free(r);
    BN_free(bne);

// Recording the end clock tick.
    end = clock();

    // Calculating total time taken by the program.
    double time_taken = double(end - start) / double(CLOCKS_PER_SEC);
    cout << "Time taken by program is : " << fixed
         << time_taken;
    cout << " sec " << endl;
    cout<<"---------------------------------------------------------------------"<<endl;


    return (ret == 1);
}


BIGNUM* USER::ping_tx(){
    /* Recording the starting clock tick.*/
    start = clock();
    BIGNUM *tx_msg;

    tx_msg = BN_new();


    ctx = BN_CTX_new();


    if(BN_mod_exp(tx_msg,g,x,p,ctx) == 0) {   //g^x mod p
        printf("Error in BN_exp\n");
    }
    else{
        BN_CTX_free(ctx);
        cout<<"Transmitted PING is: "<<endl;
        BN_print_fp(stdout,tx_msg);
        cout<<endl<<endl;

        // Recording the end clock tick.
        end = clock();

        // Calculating total time taken by the program.
        double time_taken = double(end - start) / double(CLOCKS_PER_SEC);
        cout << "Time taken by program is : " << fixed
             << time_taken;
        cout << " sec " << endl;
        cout<<"---------------------------------------------------------------------"<<endl;


        return tx_msg;
    }

}

void USER::ping_rx(BIGNUM* incoming_msg){
    /* Recording the starting clock tick.*/
    start = clock();
   cout<<"A Ping is Recieved!"<<endl;

   rx_msg = BN_new();
   rx_msg = incoming_msg;

    // Recording the end clock tick.
    end = clock();

    // Calculating total time taken by the program.
    double time_taken = double(end - start) / double(CLOCKS_PER_SEC);
    cout << "Time taken by program is : " << fixed
         << time_taken;
    cout << " sec " << endl;
    cout<<"---------------------------------------------------------------------"<<endl;

}

BIGNUM* USER::pong_tx(){
//user is bob

    /* Recording the starting clock tick.*/
    start = clock();

    BIGNUM *tx_msg, *key_msg, *sign_content, *signature_bn, *encrypted_msg;

    tx_msg = BN_new();
    key_msg = BN_new();
    sign_content = BN_new();

    ctx = BN_CTX_new();



    cout<<"Computing Shared Secret.."<<endl;


    if(BN_mod_exp(shared_sec,rx_msg,x,p,ctx) == 0) {  //tx_msg = shared_secret = (g^x mod p)^y mod p
                                                        // , rx_msg = g^x mod p
        printf("Error in BN_exp\n");
    }
    else{
        derive_keys();

        cout<<"Sending PONG..."<<endl;

        BN_mod_exp(key_msg,g,x,p,ctx); //key_msg = g^y mod p

        BN_copy(sign_content,key_msg);
        BN_lshift(sign_content,sign_content,256);
        BN_add(sign_content,sign_content,rx_msg);   // sign_content = g^y mod p | g^x mod p

        cout<<"Sign_content (g^y mod p | g^x mod p): "<<endl;
        BN_print_fp(stdout,sign_content);
        cout<<endl<<endl;

       signature_bn = digital_signature(sign_content);

       encrypted_msg = encrypt(signature_bn);    // encrypted_msg || iv_enc

       BN_lshift(encrypted_msg,encrypted_msg,256);
       BN_add(tx_msg,encrypted_msg,key_msg);    // encrypted_msg || iv_enc || key_msg

        cout<<"Transmitted PONG is:"<<endl;
        BN_print_fp(stdout,tx_msg);
        cout<<endl<<endl;

        BN_CTX_free(ctx);
        BN_free(key_msg);
        BN_free(sign_content);
        BN_free(encrypted_msg);

        // Recording the end clock tick.
        end = clock();

        // Calculating total time taken by the program.
        double time_taken = double(end - start) / double(CLOCKS_PER_SEC);
        cout << "Time taken by program is : " << fixed
             << time_taken;
        cout << " sec " << endl;
        cout<<"---------------------------------------------------------------------"<<endl;

        return tx_msg;
    }



}

void USER::pong_rx(string name,BIGNUM* incoming_msg){
    //user is alice
/* Recording the starting clock tick.*/
    start = clock();

    BIGNUM* key_msg, *incoming_signature, *ciphertext, *temp;
    BN_CTX *ctx_pong;

    ctx_pong = BN_CTX_new();

    temp = BN_new();
    key_msg = BN_new();
    ciphertext = BN_new();
    rx_msg = BN_new();

    cout<<"A Pong is Recieved!"<<endl;

    cout<<"Detaching the message in order to compute shared secret..."<<endl;

    BN_copy(rx_msg,incoming_msg);
    BN_mask_bits(rx_msg,256);
    BN_copy(key_msg,rx_msg);    //storing rx_msg = g^y mod p for future..

//    cout<<"After Masking.. ";
//    BN_print_fp(stdout,key_msg);
//    cout<<endl<<endl;

    cout<<"Computing Shared Secret.."<<endl;

    BN_mod_exp(shared_sec,key_msg,x,p,ctx_pong);    //key_msg = (g^y mod p)

    BN_CTX_free(ctx_pong);

    cout<<"Deriving Keys for Encryption and MAC process"<<endl;

    derive_keys();


    cout<<endl<<"Decrypting the first part of the message"<<endl;

    BN_rshift(ciphertext,incoming_msg,256);     // encrypted_msg || iv_enc

    cout<<"Ciphertext | iv_enc : "<<endl;

    BN_print_fp(stdout,ciphertext);
    cout<<endl<<endl;

    incoming_signature = decrypt(ciphertext);

    //Stripping the padding from signature...

    BN_rshift(incoming_signature,incoming_signature,32*4);


    cout<<"Decrypted Signature: "<<endl;
    BN_print_fp(stdout,incoming_signature);
    cout<<endl<<endl;
    cout<<"Checking the Decrypted Signature.."<<endl;

    ctx_pong = BN_CTX_new();
    BN_mod_exp(temp,g,x,p,ctx_pong);    //  temp = g^x mod p
    BN_lshift(key_msg,key_msg,256);
    BN_add(key_msg,key_msg,temp);       // key_msg = g^y mod p | g^x mod p

    //hashing the message in order to check the signature..

    // Initialize SHA1 context
    unsigned char hash[SHA_DIGEST_LENGTH];
    unsigned char keymsg_arr[BN_num_bytes(key_msg)];
    BN_bn2binpad(key_msg,keymsg_arr,BN_num_bytes(key_msg));

//    cout<<"key_msg raw"<<endl;
//    BN_print_fp(stdout,key_msg);
//    cout<<endl<<endl;

    // hashing..
    SHA1(keymsg_arr,BN_num_bytes(key_msg),hash);

    BN_bin2bn(hash,SHA_DIGEST_LENGTH,key_msg);

//    cout<<"key_msg hashed"<<endl;
//    BN_print_fp(stdout,key_msg);
//    cout<<endl<<endl;

    check_digsign(name,key_msg,incoming_signature);

    BN_free(key_msg);
    BN_free(incoming_signature);
    BN_free(ciphertext);
    BN_free(temp);
    BN_CTX_free(ctx_pong);

    // Recording the end clock tick.
    end = clock();

    // Calculating total time taken by the program.
    double time_taken = double(end - start) / double(CLOCKS_PER_SEC);
    cout << "Time taken by program is : " << fixed
         << time_taken;
    cout << " sec " << endl;
    cout<<"---------------------------------------------------------------------"<<endl;

}



void USER::derive_keys() {

    // Initialize SHA1 context
    unsigned char hash[SHA_DIGEST_LENGTH];
    unsigned char temp_arr[BN_num_bytes(shared_sec)];

    BIGNUM *temp;

    temp = BN_new();

    cout<<user_name<<"'s shared secret = \n";
    BN_print_fp(stdout,shared_sec);
    cout<<endl<<endl;

    cout<<"Deriving keys..."<<endl<<endl;
    BN_lshift(temp,shared_sec,8);
    BN_add_word(temp,0x0F);

    BN_bn2binpad(temp,temp_arr,BN_num_bytes(temp));

    SHA1(temp_arr,BN_num_bytes(temp),hash);

    BN_bin2bn( hash,16,secret_encryptkey);
    cout<<"SECRET ENCRYPTKEY = \n";
    BN_print_fp(stdout,secret_encryptkey);
    cout<<endl;

    BN_add_word(temp,0xE1);

    BN_bn2binpad(temp,temp_arr,BN_num_bytes(temp));

    SHA1(temp_arr,BN_num_bytes(temp),hash);


    BN_bin2bn( hash,16,secret_MACkey);
    cout<<"SECRET MACKEY = \n";
    BN_print_fp(stdout,secret_MACkey);
    cout<<endl<<endl;

    BN_free(temp);

}

BIGNUM* USER::digital_signature(BIGNUM* sign_content){

//    unsigned char hash[SHA_DIGEST_LENGTH];

    BIGNUM* signature_bn ,*hash_bn;

    signature_bn = BN_new();
    hash_bn = BN_new();

    // Initialize SHA1 context
    unsigned char hash[SHA_DIGEST_LENGTH];
    unsigned char sign_content_arr[BN_num_bytes(sign_content)];
    BN_bn2binpad(sign_content,sign_content_arr,BN_num_bytes(sign_content));

    // hashing..
    SHA1(sign_content_arr,BN_num_bytes(sign_content),hash);

//    SHA_CTX sha_ctx;
//    SHA1_Init (&sha_ctx);
//
//    SHA1_Update (&sha_ctx, sign_content, BN_num_bytes(sign_content));
//    SHA1_Final (hash, &sha_ctx);

    // Now we need to pad the hashed content in order to encrypt it with RSA..
    // there are two main options : RSA_sign or private_encrpyt. We need a key for both of them.
    // so firstly we need to read the generated RSA key!

    BN_bin2bn(hash,SHA_DIGEST_LENGTH,hash_bn);

    cout<<endl<<"Generated Hash (Input of RSA_sign): "<<endl;
    BN_print_fp(stdout,hash_bn);
    cout<<endl<<endl;

    FILE*   f;
    RSA* privRSA = RSA_new();
    string temp;
    temp = user_name;
    f = fopen(temp.append("_private.pem").c_str(), "r");
    PEM_read_RSAPrivateKey(f,&privRSA,NULL,NULL);


    unsigned char signature [RSA_size(privRSA)];  //memory allocation
    RSA_private_encrypt(sizeof(hash), hash, signature,privRSA,RSA_PKCS1_PADDING);   //using asymmetric priv key


    BN_bin2bn(signature,RSA_size(privRSA),signature_bn);

    cout<<"Calculated Signature: "<<endl;
    BN_print_fp(stdout, signature_bn);
    cout<<endl<<endl;

    fclose(f);
    RSA_free(privRSA);
    return signature_bn;

}

bool USER::check_digsign(string name,BIGNUM* plaintext, BIGNUM* ciphertext) {
    BIGNUM *decrypted;

    decrypted = BN_new();

    FILE*   f;
    RSA* pubRSA = RSA_new();
    string temp;
    temp = name;
    f = fopen(temp.append("_public.pem").c_str(), "r"); //gets the public key of the other user..

    PEM_read_RSAPublicKey(f,&pubRSA,NULL,NULL);


    unsigned char decrypted_arr [RSA_size(pubRSA)];  //memory allocation
    unsigned char ciphertext_arr [BN_num_bytes(ciphertext)];  //memory allocation

    BN_bn2binpad(ciphertext,ciphertext_arr,BN_num_bytes(ciphertext));

    RSA_public_decrypt(BN_num_bytes(ciphertext),ciphertext_arr,decrypted_arr,pubRSA,RSA_PKCS1_PADDING);

    BN_bin2bn(decrypted_arr,SHA_DIGEST_LENGTH,decrypted);

    //decrypted array is actually a message digest
    cout<<endl<<"RSA Decrypted Message (HASH): "<<endl;
    BN_print_fp(stdout,decrypted);
    cout<<endl;

    cout<<endl<<"Generated (HASH): "<<endl;
    BN_print_fp(stdout,plaintext);
    cout<<endl;

    if(BN_cmp(plaintext, decrypted) == 0){   // hash((g^y mod p | g^x mod p)) = key_msg
        cout<<"Signature Verified. Hi, " + name <<"!"<<endl;
    }
    else{
        cout<<"Something is wrong!"<<endl;
    }

    fclose(f);
    RSA_free(pubRSA);
    return BN_cmp(plaintext, decrypted) == 0;
}


BIGNUM * USER::encrypt(BIGNUM* plaintext) {

    BIGNUM * ciphertext, *iv_bn, *padded_bn;
    ciphertext = BN_new();
    padded_bn = BN_new();
    iv_bn = BN_new();


    //128-bit AES-CBC Encryption
    unsigned char iv_enc[AES_BLOCK_SIZE], key_array[16], plaintext_arr[(BN_num_bytes(plaintext))];
    RAND_bytes(iv_enc, AES_BLOCK_SIZE);
    BN_bin2bn(iv_enc,AES_BLOCK_SIZE,iv_bn);

    //Setting the key..
    AES_KEY enc_key;

    BN_bn2binpad(secret_encryptkey,key_array,16);
    BN_bn2binpad(plaintext,plaintext_arr,BN_num_bytes(plaintext));

    AES_set_encrypt_key((key_array), 128, &enc_key);

    //PADDING SCHEME

    const int UserDataSize = (BN_num_bytes(plaintext)); //ilerde ise yarayabilir!
    int RequiredPadding = (AES_BLOCK_SIZE - ((BN_num_bytes(plaintext) % AES_BLOCK_SIZE)));   // Calculate required padding

    vector<unsigned char> PaddedTxt(plaintext_arr, plaintext_arr+(BN_num_bytes(plaintext)));   // Easier to Pad as a vector
    for(int i=0; i < RequiredPadding; i++) {
        if (i==0) {
            PaddedTxt.push_back(0x80); //  Increase the size of the string by
        }                           //  how much padding is necessary
        else {
            PaddedTxt.push_back(0);
        }
    }

    unsigned char * UserData = &PaddedTxt[0];// Get the padded text as an unsigned char array
    const int UserDataSizePadded = (const int)PaddedTxt.size();// and the length (OpenSSl is a C-API)

    BN_bin2bn(UserData,UserDataSizePadded,padded_bn);

//    cout<<"AES-128bit CBC Encryption Padded PlainText: "<<endl;
//    BN_print_fp(stdout, padded_bn);
//    cout<<endl<<endl;

    //Padding finished! Encryption starts..

    unsigned char enc_data [UserDataSizePadded];

    AES_cbc_encrypt(UserData,enc_data,UserDataSizePadded, &enc_key, iv_enc,AES_ENCRYPT);

    BN_bin2bn(enc_data,UserDataSizePadded,ciphertext);

//    cout<<"Ciphertext: "<<endl;
//    BN_print_fp(stdout,ciphertext);
//    cout<<endl;

    BN_lshift(ciphertext,ciphertext,AES_BLOCK_SIZE*8);
//    cout<<"LSHIFT Ciphertext: "<<endl;
//    BN_print_fp(stdout,ciphertext);
//    cout<<endl;

    BN_add(ciphertext,ciphertext,iv_bn);

//    cout<<"Encrypted Message is (iv_enc at the end):  "<<endl;
//    BN_print_fp(stdout, ciphertext);
//    cout<<endl<<endl;
    BN_free(padded_bn);
    BN_free(iv_bn);
    return ciphertext;

}

BIGNUM * USER::decrypt(BIGNUM *ciphertext) {

// ciphertext = encrypted_msg || iv_enc

    unsigned char iv_enc[AES_BLOCK_SIZE], key_array[16], ciphertext_arr[(BN_num_bytes(ciphertext))];
    unsigned char encrypted_arr[(BN_num_bytes(ciphertext))-AES_BLOCK_SIZE]; //the array that we'll decrypt

    BN_bn2binpad(ciphertext,ciphertext_arr,(BN_num_bytes(ciphertext)));

    for(int i = 0; i<AES_BLOCK_SIZE ; i++){

        iv_enc[i] = ciphertext_arr[BN_num_bytes(ciphertext)-AES_BLOCK_SIZE+i];

    }

    for(int i = 0; i<(BN_num_bytes(ciphertext)-AES_BLOCK_SIZE); i++){

        encrypted_arr[i] = ciphertext_arr[i];

    }

    BIGNUM * plaintext;
    plaintext = BN_new();

    AES_KEY dec_key;

    //128-bit AES-CBC Decryption

    BN_bn2binpad(secret_encryptkey,key_array,16);
    AES_set_decrypt_key(key_array, 128, &dec_key);

    const size_t decslength =(BN_num_bytes(ciphertext))-AES_BLOCK_SIZE;
    unsigned char plaintext_arr [decslength];

    AES_cbc_encrypt(encrypted_arr, plaintext_arr, decslength, &dec_key, iv_enc, AES_DECRYPT);


    BN_bin2bn(plaintext_arr,decslength,plaintext);

    return plaintext;

}

BIGNUM * USER::MAC(BIGNUM* message_bd){ //message_bd = encrypted data|iv

    BIGNUM * ciphertext, *iv_bn, *padded_bn;
    ciphertext = BN_new();
    padded_bn = BN_new();
    iv_bn = BN_new();

    //128-bit CBC-MAC
    unsigned char iv_enc[AES_BLOCK_SIZE] = {0}; //IV set to zero for CBC-MAC
    unsigned char key_array[16], plaintext_arr[(BN_num_bytes(message_bd))];
    BN_bin2bn(iv_enc,AES_BLOCK_SIZE,iv_bn);

    //Setting the key..
    AES_KEY enc_key;

    BN_bn2binpad(secret_MACkey,key_array,16);
    BN_bn2binpad(message_bd,plaintext_arr,BN_num_bytes(message_bd));

    AES_set_encrypt_key((key_array), 128, &enc_key);

    //PADDING SCHEME

    const int UserDataSize = (BN_num_bytes(message_bd)); //ilerde ise yarayabilir!
    int RequiredPadding = (AES_BLOCK_SIZE - ((BN_num_bytes(message_bd) % AES_BLOCK_SIZE)));   // Calculate required padding

    vector<unsigned char> PaddedTxt(plaintext_arr, plaintext_arr+(BN_num_bytes(message_bd)));   // Easier to Pad as a vector
    for(int i=0; i < RequiredPadding; i++) {
        if (i==0) {
            PaddedTxt.push_back(0x80); //  Increase the size of the string by
        }                           //  how much padding is necessary
        else {
            PaddedTxt.push_back(0);
        }
    }

    unsigned char * UserData = &PaddedTxt[0];// Get the padded text as an unsigned char array
    const int UserDataSizePadded = (const int)PaddedTxt.size();// and the length

    BN_bin2bn(UserData,UserDataSizePadded,padded_bn);


    //Padding finished! Encryption starts..

    unsigned char enc_data [UserDataSizePadded];

    AES_cbc_encrypt(UserData,enc_data,UserDataSizePadded, &enc_key, iv_enc,AES_ENCRYPT);

    BN_bin2bn(enc_data,UserDataSizePadded,ciphertext);

    BN_mask_bits(ciphertext,AES_BLOCK_SIZE*8);  //taking the last block

    BN_free(padded_bn);
    BN_free(iv_bn);
    return ciphertext;

}

bool USER::check_MAC(BIGNUM* incoming_data, BIGNUM* incoming_MAC) {

    BIGNUM* BNcalculated_mac;

    BNcalculated_mac = MAC(incoming_data);

    int ret = BN_cmp(incoming_MAC, BNcalculated_mac);

    BN_free(BNcalculated_mac);
    return  ret==0;

}

BIGNUM *USER::txFirstData(string data_in) {
    //alice sends the first data!

/* Recording the starting clock tick.*/
    start = clock();


    BIGNUM *signature_content, *signature, *plaintext, *ciphertext, *tx_msg, *mac_bn, *data;
    BN_CTX *ctx_firstData;

    signature_content = BN_new();
    plaintext = BN_new();
    tx_msg = BN_new();
    data = BN_new();

    ctx_firstData = BN_CTX_new();

    BN_bin2bn(reinterpret_cast<const unsigned char *>(data_in.c_str()), data_in.length(), data);

    //Generating the signature content = g^x mod p | g^y mod p

    BN_mod_exp(signature_content,g,x,p,ctx_firstData);            //signature_content = g^x mod p
    BN_lshift(rx_msg,rx_msg,256); // preparing to concate g^y mod p to signature_content
    BN_add(signature_content,signature_content,rx_msg); //signature_content = g^x mod p | g^y mod p

    BN_CTX_free(ctx_firstData);

    //Digital Signature of the Content..

    cout<<"Sign_content (g^x mod p | g^y mod p): "<<endl;
    BN_print_fp(stdout,signature_content);
    cout<<endl;

    signature = digital_signature(signature_content);

    cout<<"First Content: "<<endl;
//    BN_print_fp(stdout,data);
//    cout<<endl<<endl;
    unsigned char data_arr [BN_num_bytes(data)];
    BN_bn2binpad(data,data_arr,BN_num_bytes(data));

    for(int i=0; i<BN_num_bytes(data); i++){

        printf("%c", data_arr[i]);

    }
    cout<<endl;

    BN_lshift(plaintext,data,BN_num_bytes(signature)*8);
//
//    cout<<"LSHIFT Data: "<<endl;
//    BN_print_fp(stdout,plaintext);
//    cout<<endl;

    BN_add(plaintext,plaintext,signature);

//    cout<<"Plaintext: "<<endl;
//    BN_print_fp(stdout,plaintext);
//    cout<<endl;

    ciphertext = encrypt(plaintext);    // ENC(data|signature) | IV

    cout<<"Encryption Finished.. MAC computation starts.."<<endl;
    mac_bn = MAC(ciphertext);   // calculating the mac of ENC(data|signature) | IV

    cout<<"MAC: "<<endl;
    BN_print_fp(stdout,mac_bn);
    cout<<endl<<endl;

//    cout<<endl<<endl;
//    cout<<"mac_bn length = ";
//    cout<<BN_num_bits(mac_bn);
//    cout<<endl;

    BN_lshift(tx_msg,ciphertext,8*BN_num_bytes(mac_bn));
    BN_add(tx_msg,tx_msg,mac_bn);   // tx_msg = ENC(data|signature) | IV |mac

    cout<<"Transmission of the first data message is finished!"<<endl;
    BN_free(ciphertext);
    BN_free(plaintext);
    BN_free(signature_content);
    BN_free(data);
    BN_free(mac_bn);

    // Recording the end clock tick.
    end = clock();

    // Calculating total time taken by the program.
    double time_taken = double(end - start) / double(CLOCKS_PER_SEC);
    cout << "Time taken by program is : " << fixed
         << time_taken;
    cout << " sec " << endl;
    cout<<"---------------------------------------------------------------------"<<endl;

    return tx_msg;

}

void USER::rxFirstData(string name,BIGNUM *incoming_msg) {   //bob recieves the first data!

    /* Recording the starting clock tick.*/
    start = clock();

    BIGNUM *ciphertext, *mac_in, *content, *sign_in, *sign_calc;

    mac_in = BN_new();
    ciphertext = BN_new();
    sign_in = BN_new();

    //First, slice the data into Ciphertext and MAC blocks

    BN_rshift(ciphertext, incoming_msg, AES_BLOCK_SIZE*8);

    cout<<"Ciphertext =  ";
    BN_print_fp(stdout, ciphertext);
    cout<<endl;

    BN_copy(mac_in,incoming_msg);
    BN_mask_bits(mac_in,128);

    cout<<"Incoming MAC =  ";
    BN_print_fp(stdout, mac_in);
    cout<<endl;

    cout<<"Comparing MAC values.."<<endl;

    if(check_MAC(ciphertext,mac_in)){
        cout<<"MAC values are equal! Decrypting the content..."<<endl;
    }
    else cout<<"MAC COMPARISON ERROR!"<<endl;

    content = decrypt(ciphertext);  // content = data|signature

    cout<<"Content is decrypted! Splitting the signature in order to confirm the authentication..."<<endl;

    BIGNUM *mod_calc, *hash_bn;
    BN_CTX *sign_ctx;
    sign_ctx = BN_CTX_new();
    sign_calc = BN_new();
    mod_calc = BN_new();
    hash_bn = BN_new();

    BN_copy(sign_in,content);

    unsigned char temp[BN_num_bytes(sign_in)];
    BN_bn2binpad(sign_in,temp,BN_num_bytes(sign_in));

    //Strip the padding from signature...
    for(int i=BN_num_bytes(sign_in); i>0 ; i--){

        if(temp[i-1] == 0x00){
            BN_rshift(sign_in,sign_in,8);
            }
        else if(temp[i-1] == 0x80){
            BN_rshift(sign_in,sign_in,8);
            break;
        }
        else break;

    }

    BN_copy(content,sign_in);
    BN_rshift(content,content,512);
    BN_mask_bits(sign_in,512);    //digital signature is done using RSA-512


    BN_mod_exp(mod_calc,g,x,p,sign_ctx);
    BN_lshift(sign_calc,mod_calc,256);
    BN_add(sign_calc,sign_calc,rx_msg);   //sign_calc = g^x mod p | g^y mod p

    BN_CTX_free(sign_ctx);
    BN_free(mod_calc);

    // Initialize SHA1 context
    unsigned char hash[SHA_DIGEST_LENGTH];
    unsigned char sign_arr[BN_num_bytes(sign_calc)];
    BN_bn2binpad(sign_calc,sign_arr,BN_num_bytes(sign_calc));

    // hashing..
    SHA1(sign_arr,BN_num_bytes(sign_calc),hash);
    BN_bin2bn(hash,SHA_DIGEST_LENGTH,hash_bn);

//    cout<<"Sign_in : "<<endl;
//    BN_print_fp(stdout, sign_in);
//    cout<<endl;

    check_digsign(name,hash_bn,sign_in);

    // Both parties now know each other.. It is secure to communicate onwards!
    unsigned char content_arr [BN_num_bytes(content)];

    BN_bn2binpad(content,content_arr,BN_num_bytes(content));

    cout<<"Decrypted message is: ";
    for(int i=0; i<BN_num_bytes(content); i++){

        printf("%c", content_arr[i]);

    }
    cout<<endl;

    BN_free(hash_bn);
    BN_free(mac_in);
    BN_free(ciphertext);
    BN_free(content);
    BN_free(sign_in);
    BN_free(sign_calc);

    // Recording the end clock tick.
    end = clock();

    // Calculating total time taken by the program.
    double time_taken = double(end - start) / double(CLOCKS_PER_SEC);
    cout << "Time taken by program is : " << fixed
         << time_taken;
    cout << " sec " << endl;
    cout<<"---------------------------------------------------------------------"<<endl;
}

BIGNUM *USER::txData(string data_in) {
    /* Recording the starting clock tick.*/
    start = clock();
    BIGNUM* data, *ciphertext, *mac_bn, *tx_msg;

    data = BN_new();
    ciphertext = BN_new();
    mac_bn = BN_new();
    tx_msg = BN_new();

    BN_bin2bn(reinterpret_cast<const unsigned char *>(data_in.c_str()), data_in.length(), data);

    ciphertext = encrypt(data);
    mac_bn = MAC(ciphertext);

    BN_lshift(tx_msg,ciphertext,BN_num_bytes(mac_bn)*8);
    BN_add(tx_msg,tx_msg,mac_bn);

    BN_free(data);
    BN_free(mac_bn);
    BN_free(ciphertext);

    // Recording the end clock tick.
    end = clock();

    // Calculating total time taken by the program.
    double time_taken = double(end - start) / double(CLOCKS_PER_SEC);
    cout << "Time taken by program is : " << fixed
         << time_taken;
    cout << " sec " << endl;
    cout<<"---------------------------------------------------------------------"<<endl;

    return tx_msg;
}

void USER::rxData(BIGNUM *incoming_msg) {
    /* Recording the starting clock tick.*/
    start = clock();

    BIGNUM *plaintext, *ciphertext, *mac_in;

    ciphertext = BN_new();

    mac_in = BN_new();
    BN_copy(mac_in,incoming_msg);
    BN_mask_bits(mac_in,128);


    BN_rshift(ciphertext, incoming_msg, AES_BLOCK_SIZE*8);

    if(check_MAC(ciphertext,mac_in)){

        plaintext = decrypt(ciphertext);

        //Strip the padding from signature...
        unsigned char plaintext_arr[BN_num_bytes(plaintext)];
        BN_bn2binpad(plaintext,plaintext_arr,BN_num_bytes(plaintext));

        for(int i=BN_num_bytes(plaintext); i>0 ; i--){

            if(plaintext_arr[i-1] == 0x00){
                BN_rshift(plaintext,plaintext,8);
            }
            else if(plaintext_arr[i-1] == 0x80){
                BN_rshift(plaintext,plaintext,8);
                break;
            }
            else break;
        }

        BN_bn2binpad(plaintext,plaintext_arr,BN_num_bytes(plaintext));
        cout<<user_name<<" decrypts the message: ";
        for(int i=0; i<BN_num_bytes(plaintext); i++){

            printf("%c", plaintext_arr[i]);

        }
        cout<<endl;
        BN_free(mac_in);
        BN_free(plaintext);
        BN_free(ciphertext);

        // Recording the end clock tick.
        end = clock();

        // Calculating total time taken by the program.
        double time_taken = double(end - start) / double(CLOCKS_PER_SEC);
        cout << "Time taken by program is : " << fixed
             << time_taken;
        cout << " sec " << endl;
        cout<<"---------------------------------------------------------------------"<<endl;

    }
    else{

        cout<<"MAC ERROR!"<<endl;

    }

}



