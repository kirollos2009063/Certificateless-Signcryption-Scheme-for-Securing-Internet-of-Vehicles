/*
 * TAPublicKey.h
 *
 *  Created on: Apr 25, 2024
 *      Author: Lenovo
 */

#ifndef TAPUBLICKEY_H_
#define TAPUBLICKEY_H_

#include <Crypto++/eccrypto.h>

using namespace CryptoPP;

class TA_PublicKey : public cMessage {
private:
    ECP::Point TAPublicKey;
    int VehicleID;
public:
    TA_PublicKey() {}
    virtual ~TA_PublicKey() {}

    // Setter and getter for TAPublicKey
    void setTAPublicKey(const ECP::Point& publicKey) { TAPublicKey = publicKey; }
    ECP::Point getTAPublicKey() const { return TAPublicKey; }

    void setVehicleID(const int& value) { VehicleID = value; }
    int getVehicleID() const { return VehicleID;}

};



#endif /* TAPUBLICKEY_H_ */
