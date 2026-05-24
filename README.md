# CA
uruchomienie:
mkdir build
cmake -S . -B build
cmake --build build
./build/exe demo

usuwanie:
find outbox inbox temp keys ca tsp -type f -delete
rm -f *.bin *.sig *.enc *.key *.data message.txt
