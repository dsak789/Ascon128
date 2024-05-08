void setup() {
  Serial.begin(9600); // Initialize serial communication
}

void loop() {
  for (int i = 0; i < 50; i++) {
    Serial.println("Hello, world!");
  }
  
  delay(1000); // Delay for 1 second before repeating
}

// ram usage 
// throughput
// input size
// output size