
PORT := 8192

run_server_v4: server_v4
	./server_v4 $(PORT)

server_v4: server_v4.cpp
	g++ -o $@ $^ -I ../kmod/

run_server_v6: server_v6
	./server_v6 $(PORT)

server_v6: server_v6.cpp
	g++ -o $@ $^ -I ../kmod/


run_client_opp_v4: client_opp_v4
	./client_opp_v4 127.0.0.1 1122 127.0.0.1 8192 10.0.0.1 1 

client_opp_v4: client_opp_v4.c common.h
	gcc -o $@ $^ -I ../kmod


run_client_opp_v6: client_opp_v6
	./client_opp_v6 ::1 1122 ::1 8192 fdbd::1 1 

client_opp_v6: client_opp_v6.c common.h
	gcc -o $@ $^ -I ../kmod
