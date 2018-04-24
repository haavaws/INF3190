all: transport_daemon routing_daemon mip_daemon client server

transport_daemon: transport.c transport_daemon.c
	gcc -std=gnu99 transport.c transport_daemon.c -o transport_daemon

routing_daemon: routing.c routing_daemon.c
	gcc -std=gnu99 routing.c routing_daemon.c -o routing_daemon

mip_daemon: mip.c sockets.c debug.c mip_daemon.c
	gcc -std=gnu99 mip.c sockets.c debug.c mip_daemon.c -o mip_daemon

client: client.c
	gcc -std=gnu99 client.c -o client

server: server.c
	gcc -std=gnu99 server.c -o server




run_mip_a: mip_daemon
	./mip_daemon -d AppA RouteA FwdA 10

run_mip_b: mip_daemon
	./mip_daemon -d AppB RouteB FwdB 20 30 40

run_mip_c: mip_daemon
	./mip_daemon -d AppC RouteC FwdC 50 60

run_mip_d: mip_daemon
	./mip_daemon -d AppD RouteD FwdD 70 80 90

run_mip_e: mip_daemon
	./mip_daemon -d AppE RouteE FwdE 100




run_route_a: routing_daemon
	./routing_daemon -d RouteA FwdA

run_route_b: routing_daemon
	./routing_daemon -d RouteB FwdB

run_route_c: routing_daemon
	./routing_daemon -d RouteC FwdC

run_route_d: routing_daemon
	./routing_daemon -d RouteD FwdD

run_route_e: routing_daemon
	./routing_daemon -d RouteE FwdE




run_serv_a: server
	./server AppA

run_serv_b: server
	./server AppB

run_serv_c: server
	./server AppC

run_serv_d: server
	./server AppD

run_serv_e: server
	./server AppE




run_ping_a_e: client
	./client 100 testing AppA
