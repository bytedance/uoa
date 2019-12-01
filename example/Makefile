

.PHONY: run_server_v4 run_client_v4


run_server_v4: server_v4
	./server_v4

run_client_v4: client_v4
	./client_v4 127.0.0.1 

server_v4: server_v4.cpp
	g++ -o $@ $^

client_v4: client_v4.cpp
	g++ -o $@ $^
