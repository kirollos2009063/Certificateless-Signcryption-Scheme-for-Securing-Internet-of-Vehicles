#include<omnetpp.h>
#include <Crypto++/sha.h>
#include <Crypto++/sha3.h>
#include <Crypto++/eccrypto.h>
#include <Crypto++/oids.h>
#include <Crypto++/hex.h>
#include <Crypto++/osrng.h>
#include<string>

using namespace omnetpp;
using namespace CryptoPP;
using namespace std;
#ifndef Encrypted_Msg_H_
#define Encrypted_Msg_H_

class Encrypted_Msgr : public cMessage {

private:
    string Message;
public:
        int  DestID=3;
        Encrypted_Msgr(const char *name = nullptr, int kind = 0,int originalRSUId=0);
        ~Encrypted_Msgr();

        void setMessage(const string& value) { Message = value; }
        string getMessage() const { return Message; }

};



#endif /* Encrypted_Msg_H_ */
