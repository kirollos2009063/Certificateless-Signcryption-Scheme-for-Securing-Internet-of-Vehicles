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


#ifndef FEEDBACK_H_
#define FEEDBACK_H_



class Feedback : public cMessage {

private:
    int Ack;

public:
         Feedback(const char *name = nullptr, int kind = 0);
        ~Feedback();

        void setAck(const int& value) { Ack = value; }
        int getAck() const { return Ack; }



};



#endif /* FEEDBACK_H_ */
