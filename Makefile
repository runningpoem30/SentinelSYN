
all:
	g++ -O3 main.cpp -o sentinel -lpcap

clean:
	rm -f sentinel