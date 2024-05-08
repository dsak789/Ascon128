 #include "g.h"
 int no=1;
void setup() {
  Serial.begin(9600); // Initialize serial communication
}

void loop() {
    Serial.println("Hello, world!");
    Serial.println(no);
    no = no + 1;
    void printg();
  
  delay(1000); // Delay for 1 second before repeating
}
