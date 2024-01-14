simple Vehicle
{
    
    parameters:
        @display("i=device/car;bgb=418,306");
        int src=default(2);
        int dest=default(6);
        bool isCar = true;
        bool isKGC=false;
        bool isRSU=false;
    gates:
        input Vin;
        output Vout;
     
}
