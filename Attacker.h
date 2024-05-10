/*
 * Attacker.h
 *
 *  Created on: Apr 24, 2024
 *      Author: Lenovo
 */

#ifndef ATTACKER_H_
#define ATTACKER_H_


#include <omnetpp.h>
#include <string>
#include <omnetpp.h>
#include <string>
#include "Encrypted_Msg.h"
#include "Public_Key_Req_msg.h"
#include "Partial_Priv_Key_reqMsg.h"
#include "CompromizedSharedSecretKey.h"
#include <Crypto++/aes.h>
#include <Crypto++/modes.h>
#include<TAPublicKey.h>
#include "Requested_Public_Key_Msg.h"

using namespace omnetpp;
using namespace std;

class Attacker : public cSimpleModule {
  public:
    int attackNum = 5;

  protected:
    virtual void initialize() override;
    virtual void handleMessage(cMessage *msg) override;

  private:
    AutoSeededRandomPool prng;
    pair<ECP::Point,ECP::Point> AttackerPublicKey;
    pair<Integer,Integer> AttackerPrivateKey;
    DL_GroupParameters_EC<ECP> params;
    Encrypted_Msgr *encmsg1 = nullptr;
    Public_Key_Req_Msg *public_key_req_msg = nullptr;
    Partial_Priv_Key_reqMsg *partial_priv_Key_reqMsg = nullptr;
    int messageCounter = 0; // Counter to track the number of messages sent by the attacker
    int maxMessages = 2;    // Maximum number of messages the attacker can send
    int counter=0;
    string MessageToBeTampered;

    string symmetricEncrypt(const string &plaintext, const Integer &sharedSecret);
    string symmetricDecrypt(const string &ciphertext, const Integer &sharedSecret);
    bool bruteForceAttack(const string &ciphertext, const string &plaintext);
    ECP::Point multiplyScalar(const Integer &k, const ECP::Point &P, const DL_GroupParameters_EC<ECP> &param);
};


#endif /* ATTACKER_H_ */
