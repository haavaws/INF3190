all: mip_daemon client server

mip_daemon: mip.c sockets.c debug.c mip_daemon.c
	gcc -std=gnu99 mip.c sockets.c debug.c mip_daemon.c -o mip_daemon

client: client.c
	gcc -std=gnu99 client.c -o client

server: server.c
	gcc -std=gnu99 server.c -o server
