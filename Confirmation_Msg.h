/*
 * Confirmation_Msg.h
 *
 *  Created on: Feb 23, 2024
 *      Author: Lenovo
 */

#ifndef CONFIRMATION_MSG_H_
#define CONFIRMATION_MSG_H_

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

class Confirmation_Msg : public cMessage {

private:
    bool Done;
    int VehicleID;
public:
    Confirmation_Msg(const char *name = nullptr, int kind = 0);
    ~Confirmation_Msg();  // Declare destructor

    void setDone(const bool& value) { Done = value; }
    bool getDone() const { return Done;}

    void setVehicleID(const int& value) { VehicleID = value; }
    int getVehicleID() const { return VehicleID;}

};





#endif /* CONFIRMATION_MSG_H_ */
