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
#ifndef MESSAGETOBEENC_H_
#define MESSAGETOBEENC_H_

class MessageToBeEncr : public cMessage {

private:
    string Message;
    int originalRSUId;
public:
        int  DestID=6;
        MessageToBeEncr(const char *name = nullptr, int kind = 0,int originalRSUId=0);
        ~MessageToBeEncr();

        void setMessage(const string& value) { Message = value; }
        string getMessage() const { return Message; }

        void setoriginalRSUId(int value) { int originalRSUId = value; }
        int getoriginalRSUId() const { return originalRSUId; }


};



#endif /* MESSAGETOBEENC_H_ */
