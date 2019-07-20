all: pcap_test

pcap_test: pcap_test.0
	g++ -o pcap_test pcap_test.o

pcap_test.o: main.cpp
	g++ -c -o pcap_test.o pcap_test.cpp

clean:
	rm -f pcap_test.o