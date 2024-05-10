/*
 * CompromizedSharedSecretKey.h
 *
 *  Created on: Apr 23, 2024
 *      Author: Lenovo
 */

#ifndef COMPROMIZEDSHAREDSECRETKEY_H_
#define COMPROMIZEDSHAREDSECRETKEY_H_


#include <omnetpp.h>

using namespace omnetpp;
using namespace CryptoPP;

class CompromizedSharedSecretKey : public cMessage {
private:
    Integer ComprSharedSecret;

public:
    CompromizedSharedSecretKey() : cMessage("CompromizedSharedSecretKey") {}
    virtual ~CompromizedSharedSecretKey() {}

    // Getter and setter for the ComprSharedSecret variable
    void setComprSharedSecret(Integer sharedSecret) { ComprSharedSecret = sharedSecret; }
    Integer getComprSharedSecret() const { return ComprSharedSecret; }
};


#endif /* COMPROMIZEDSHAREDSECRETKEY_H_ */
