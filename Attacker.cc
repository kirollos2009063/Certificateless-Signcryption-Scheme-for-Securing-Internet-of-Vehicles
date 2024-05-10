#include<Attacker.h>


Define_Module(Attacker);

void Attacker::initialize() {
    counter=0;

    //make sure that the attacker is being entered even if no messages is sent to it like in DOS attack
    if(attackNum==3 || attackNum==4){
    scheduleAt(0.3, new cMessage());
    }

     //Here the attacker start to generate his own public and private key
     params = ASN1::secp256r1();
     ECP::Point D = params.GetSubgroupGenerator(); //generator point
     AttackerPrivateKey.first = Integer(prng, Integer::One(), params.GetSubgroupOrder() - 1);
     AttackerPrivateKey.second = Integer(prng, Integer::One(), params.GetSubgroupOrder() - 1);

     AttackerPublicKey.first = multiplyScalar(AttackerPrivateKey.first, D, params);
     AttackerPublicKey.second = multiplyScalar(AttackerPrivateKey.second, D, params);
}

void Attacker::handleMessage(cMessage *msg) {

    //Replay Attack

  if(attackNum==1){
      //handle messages of type Encrypted_msgr
    if(Encrypted_Msgr *encmsg = dynamic_cast<Encrypted_Msgr *>(msg)){


       //Brute-Force
//     bruteForceAttack(encmsg->getMessage(),"accident on road 9 SEQ# 0");



    // Send the original message immediately to the receiver vehicle without making any changes to it
    send(encmsg, "out");

    // Increment the message counter
    messageCounter++;

    // Check if the maximum message limit has been reached
    if (messageCounter >= maxMessages) {
        return;
    }
    // we schedule the message to be sent after a period of time
    scheduleAt(simTime() + 0.1, encmsg->dup());

    }

}













   //Integrity & Authentication




if(attackNum==2){

   //handle messages of type Encrypted_Msg
   if(Encrypted_Msgr *encmsg = dynamic_cast<Encrypted_Msgr *>(msg)){
       //copy the Encrypted_Msgr received to another Encrypted_Msgr called encmsg1
       encmsg1=encmsg;
       //Extract the encrypted message and put it in variable called MessageToBeTampered
              MessageToBeTampered=encmsg->getMessage();

     }




   //handle messages of type CompromizedSharedSecretKey
   if(CompromizedSharedSecretKey *compromizedsharedsecretkey=dynamic_cast<CompromizedSharedSecretKey *>(msg)){
       //Extract the shared secret from the message
       Integer ComprSharedSecretKey=compromizedsharedsecretkey->getComprSharedSecret();
       //Decrypt the message extracted above using the shared secret extracted in the above line
       string DecryptedMessage = symmetricDecrypt(MessageToBeTampered,ComprSharedSecretKey);
       //Then tamper the decrypted message and put it in messageToBeTampered variable
       MessageToBeTampered=DecryptedMessage + " No disruption";
       //then encrypt the tampered message
       string encryptedMessage = symmetricEncrypt(MessageToBeTampered,ComprSharedSecretKey);
       //set the encrypted message with the tampered one to be sent to the Dest vehicle
       encmsg1->setMessage(encryptedMessage);
       //send the encrypted message with the tampered value
       send(encmsg1,"out");

   }
}














   // Dos attack on TA







if(attackNum==3){


    //We set counter to 0 because we want it to be called one time
    if (counter == 0) {
        for(int i = 0; i < 20; i++) {
            //create multiple instances of Public_Key_Req_Msg to be sent
            public_key_req_msg = new Public_Key_Req_Msg();
            public_key_req_msg->setID(2);
            public_key_req_msg->setSenderVehicleId(40);

            scheduleAt(simTime() + 0.3,public_key_req_msg);//calls the coming if statement after specific time
        }
        counter++;
    }

    //handle messages received of type Public_Key_Req_Msg
    if(Public_Key_Req_Msg *public_key_req_msg = dynamic_cast<Public_Key_Req_Msg *>(msg)){

        // Send the original message immediately
            send(public_key_req_msg, "out");

    }


}







    // Dos attack on KGC







if(attackNum==4){


    //We set counter to 0 because we want it to be called one time
    if (counter == 0) {
           for(int i=0;i<3;i++){
               //create multiple instances of partial_priv_Key_reqMsg to be sent
                partial_priv_Key_reqMsg = new Partial_Priv_Key_reqMsg();
                partial_priv_Key_reqMsg->setID(getId());
                scheduleAt(simTime() + 0.3,  partial_priv_Key_reqMsg); //calls the coming if statement after specific time
           }
           //increment counter to insure this part is called one time
            counter++;
        }



    //handle messages received of type Partial_Priv_Key_reqMsg
    if(Partial_Priv_Key_reqMsg *partial_priv_Key_reqMsg = dynamic_cast<Partial_Priv_Key_reqMsg *>(msg)){

           // Send the original message immediately
               send(partial_priv_Key_reqMsg, "out");

       }


    }

if(attackNum==5){
    //handle messages of type Requested_Public_Key_Msg
    if (Requested_Public_Key_Msg *requested_public_key = dynamic_cast<Requested_Public_Key_Msg *>(msg)) {
        //Change the value of requested_public_key to the public key of the attacker instead of the public key of the intended vehicle
         requested_public_key->setRequestedPublickey(AttackerPublicKey);
         //then send it again to the vehicle
         send(requested_public_key,"out2");

      }
   }

}

string Attacker::symmetricEncrypt(const string& plaintext, const Integer& sharedSecret) {
    SecByteBlock key(AES::MAX_KEYLENGTH);
    sharedSecret.Encode(key, key.size());
    CFB_Mode<AES>::Encryption encryption;
    encryption.SetKeyWithIV(key, key.size(), key);
    string ciphertext;
    StringSource(plaintext, true, new StreamTransformationFilter(encryption, new StringSink(ciphertext)));
    return ciphertext;
}

string Attacker::symmetricDecrypt(const string& ciphertext, const Integer& sharedSecret) {
    SecByteBlock key(AES::MAX_KEYLENGTH);
    sharedSecret.Encode(key, key.size());
    CFB_Mode<AES>::Decryption decryption;
    decryption.SetKeyWithIV(key, key.size(), key);
    string decryptedMessage;
    StringSource(ciphertext, true, new StreamTransformationFilter(decryption, new StringSink(decryptedMessage)));
    return decryptedMessage;
}

bool Attacker::bruteForceAttack(const string& ciphertext, const string& plaintext) {
    AutoSeededRandomPool prng;
    SecByteBlock key(AES::MAX_KEYLENGTH);

    for (size_t i = 0; i < static_cast<size_t>(std::pow(2.0, static_cast<double>(AES::MAX_KEYLENGTH))); ++i) {
        prng.GenerateBlock(key, key.size());
        string decryptedMessage = symmetricDecrypt(ciphertext, Integer(key, key.size()));
        if (decryptedMessage == plaintext) {
            EV << "Brute force attack successful! Key found: " << Integer(key, key.size()) << endl;
            return true;
        }
    }

    EV << "Brute force attack unsuccessful. No matching key found." << endl;
    return false;
}
ECP::Point Attacker::multiplyScalar(const Integer &k, const ECP::Point &P, const DL_GroupParameters_EC<ECP> &param) {
    ECP ec = param.GetCurve();
    ECP::Point result = ec.ScalarMultiply(P, k);
    return result;
}
