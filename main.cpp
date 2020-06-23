//
// Created by topalc on 20.06.2020.
//

#include "TLS_user.h"

using namespace std;
int main(){



    BIGNUM *ping_msg, *pong_msg, *pub1, *pub2, *first_data, *tx_msg;
    pub1 = BN_new();
    pub2 = BN_new();

    BN_generate_prime_ex(pub1,256,0,NULL,NULL,NULL);    //cyclic group p
    BN_generate_prime_ex(pub2,128,0,NULL,NULL,NULL);    //generator g


    cout<<"Cyclic group p:\t";
    BN_print_fp(stdout, pub1);
    cout<<endl;
    cout<<"Generator g:\t";
    BN_print_fp(stdout, pub2);
    cout<<endl;

    cout<<"---------------------------------------------------------------------"<<endl;


    cout<<"Private Parts of Alice"<<endl;
    USER Alice("Alice",pub1,pub2);
    Alice.generate_key();


    cout<<"Private Parts of Bob"<<endl;

    USER Bob("Bob",pub1,pub2);
    Bob.generate_key();

    cout<<"---------------------------------------------------------------------"<<endl;

    cout<<"Alice sends a PING"<<endl;

    ping_msg = Alice.ping_tx();

    Bob.ping_rx(ping_msg);

    cout<<"---------------------------------------------------------------------"<<endl;


    pong_msg = Bob.pong_tx();

    cout<<"---------------------------------------------------------------------"<<endl;

    Alice.pong_rx("Bob",pong_msg);

    cout<<"---------------------------------------------------------------------"<<endl;

    cout<<"Transmitting first data.."<<endl<<endl;
    first_data = Alice.txFirstData("Hello! This the first message.");

    cout<<"---------------------------------------------------------------------"<<endl;

    Bob.rxFirstData("Alice",first_data);

    cout<<"---------------------------------------------------------------------"<<endl;

    cout<<"Bob transmits.."<<endl;
    tx_msg = Bob.txData("Data broadcast starts.. This is the second message from Bob! How are you Alice?");

    Alice.rxData(tx_msg);

    cout<<"Alice transmits.."<<endl;
    tx_msg = Alice.txData("I'm fine thanks!");

    Bob.rxData(tx_msg);

    cout<<"Bob transmits.."<<endl;
    tx_msg = Bob.txData("There is an important event at 08.45 PM");

    Alice.rxData(tx_msg);

    cout<<"Bob transmits.."<<endl;
    tx_msg = Bob.txData("Hope to hear from you soon..");

    Alice.rxData(tx_msg);

    cout<<"Alice transmits.."<<endl;
    tx_msg = Alice.txData("Send me the coordinates!");

    Bob.rxData(tx_msg);

    cout<<"Bob transmits.."<<endl;
    tx_msg = Bob.txData("Latitude: 60.70701, Longitude: -134.60776, Distortion: 4.18");

    Alice.rxData(tx_msg);

    cout<<"COMMUNICATION ENDS!!";
return 0;
}
