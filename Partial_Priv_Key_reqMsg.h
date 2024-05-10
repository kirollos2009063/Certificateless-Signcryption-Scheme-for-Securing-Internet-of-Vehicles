/*
 * Partial_Priv_Key_reqMsg.h
 *
 *  Created on: Jan 11, 2024
 *      Author: Lenovo
 */

#ifndef Partial_Priv_Key_reqMsg_H_
#define Partial_Priv_Key_reqMsg_H_


#include <omnetpp.h>
#include <Crypto++/sha.h>
#include <Crypto++/sha3.h>
#include <Crypto++/eccrypto.h>
#include <Crypto++/oids.h>
#include <Crypto++/hex.h>
#include <Crypto++/osrng.h>
#include<string>

using namespace omnetpp;
using namespace CryptoPP;

class Partial_Priv_Key_reqMsg : public cMessage {

private:
    ECP::Point Od;
    int ID;

public:
    Partial_Priv_Key_reqMsg(const char *name = nullptr, int kind = 0);
    ~Partial_Priv_Key_reqMsg();  // Declare destructor
    void setOd(const ECP::Point& value) { Od = value; }
    ECP::Point getOd() const { return Od; }

    void setID(const int& value) { ID = value; }
    int getID() const { return ID; }


};



#endif /* Partial_Priv_Key_reqMsg_H_ */
