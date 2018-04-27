all: transport_daemon routing_daemon mip_daemon client server

transport_daemon: transport.c transport_daemon.c
	gcc -std=gnu99 transport.c transport_daemon.c -o transport_daemon

routing_daemon: routing.c routing_daemon.c
	gcc -std=gnu99 routing.c routing_daemon.c -o routing_daemon

mip_daemon: mip.c sockets.c debug.c mip_daemon.c
	gcc -std=gnu99 mip.c sockets.c debug.c mip_daemon.c -o mip_daemon

client: transport_client.c
	gcc -std=gnu99 transport_client.c -o client

server: transport_server.c
	gcc -std=gnu99 transport_server.c -o server




run_tp_a: transport_daemon
	./transport_daemon -d 1 appA tpA

run_tp_b: transport_daemon
	./transport_daemon -d 1 appB tpB

run_tp_c: transport_daemon
	./transport_daemon -d 1 appC tpC

run_tp_d: transport_daemon
	./transport_daemon -d 1 appD tpD

run_tp_e: transport_daemon
	./transport_deamon -d 1 appE tpE




run_mip_a: mip_daemon
	./mip_daemon -d appA routeA fwdA 10

run_mip_b: mip_daemon
	./mip_daemon -d appB routeB fwdB 20 30 40

run_mip_c: mip_daemon
	./mip_daemon -d appC routeC fwdC 50 60

run_mip_d: mip_daemon
	./mip_daemon -d appD routeD fwdD 70 80 90

run_mip_e: mip_daemon
	./mip_daemon -d appE routeE fwdE 100




run_route_a: routing_daemon
	./routing_daemon -d routeA fwdA

run_route_b: routing_daemon
	./routing_daemon -d routeB fwdB

run_route_c: routing_daemon
	./routing_daemon -d routeC fwdC

run_route_d: routing_daemon
	./routing_daemon -d routeD fwdD

run_route_e: routing_daemon
	./routing_daemon -d routeE fwdE




run_serv_a: server
	./server 80 tpA

run_serv_b: server
	./server 80 tpB

run_serv_c: server
	./server 80 tpC

run_serv_d: server
	./server 80 tpD

run_serv_e: server
	./server 80 tpE




run_transfer_a_e: client
	./client 100 tpA 100 80 mip.c
