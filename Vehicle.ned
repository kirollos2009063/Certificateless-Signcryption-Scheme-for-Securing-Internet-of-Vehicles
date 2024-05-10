simple Vehicle
{
    
    parameters:
        @display("i=device/car;bgb=418,306");
        int src=default(2);
        int dest=default(20);
        bool isCar = true;
    gates:
        input Vin;
        input Vin2;
        output Vout;
        output Vout2;
        
}
