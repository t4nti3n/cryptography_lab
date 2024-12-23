To run the CLI file task.cpp, follow these steps:

Build the file: Use the build task defined in your tasks.json to compile the task.cpp file. Open the terminal in Visual Studio Code and run the following command:
g++ -g2 -O3 -DNDEBUG lab3/task.cpp -o lab3/task.exe -D_WIN32_WINNT=0x0A00 -pthread -LC:/cryptopp/lib/cryptopp/gcc -lcryptopp -IC:/cryptopp/include/cryptopp -Wall
Run the executable: After building the file, you can run the executable with the appropriate command and arguments. Here are examples of how to use the commands:

Generate RSA key pair:
./lab3/task.exe generate 2048 private_key.pem public_key.pem PEM
Encrypt text:
./lab3/task.exe encrypt "Hello, World!" public_key.pem cipher.txt base64
Decrypt text:
./lab3/task.exe decrypt cipher.txt private_key.pem plain_text.txt base64
