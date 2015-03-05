/*
 * proxy.c
 *
 *  Created on: Feb 15, 2015
 *      Author: Blair
 */

#include "proxy_parse.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netdb.h>

enum {MAX_NUM_CHILD = 20}; /* Maximum number of child processes */

static int numChild; /* Current number of child processes running */
static int errMessageLen = 31; /* Length of errMessage */
const char *pcPgmName;
/* Error message to send to client */
const char *errMessage = "HTTP/1.0 500 INTERNAL ERROR\r\n\r\n";


/* Create, bind, and listen on a stream socket on port pcPort and return socket */
static int createServerSocket(char *pcPort) {
	enum {BACKLOG = 50};

  struct addrinfo aHints, *paRes;
  int iSockfd;

  /* Get address information for stream socket on input port */
  memset(&aHints, 0, sizeof(aHints));
  aHints.ai_family = AF_UNSPEC;
  aHints.ai_socktype = SOCK_STREAM;
  aHints.ai_flags = AI_PASSIVE;
  if (getaddrinfo(NULL, pcPort, &aHints, &paRes) < 0) {
      perror("GETADDR error");
      exit(EXIT_FAILURE);
  }

  /* Create, bind, listen */
  if ((iSockfd = socket(paRes->ai_family, paRes->ai_socktype, paRes->ai_protocol)) < 0) {
    perror("CREATE error");
    exit(EXIT_FAILURE);
  }
  if (bind(iSockfd, paRes->ai_addr, paRes->ai_addrlen) < 0) {
    perror("BIND error");
    exit(EXIT_FAILURE);
  }
  if (listen(iSockfd, BACKLOG) < 0) {
    perror("LISTEN error");
    exit(EXIT_FAILURE);
  }

  /* Free paRes, which was dynamically allocated by getaddrinfo */
  freeaddrinfo(paRes);

  return iSockfd;
}

/* Create a socket and connect to address pcAddress and port pcPort, and return socket */
static int createClientSocket(char *pcAddress, char *pcPort) {
  struct addrinfo aHints, *paRes;
  int iSockfd;

  /* Get address information for stream socket on input port */
  memset(&aHints, 0, sizeof(aHints));
  aHints.ai_family = AF_UNSPEC;
  aHints.ai_socktype = SOCK_STREAM;
  if (getaddrinfo(pcAddress, pcPort, &aHints, &paRes) != 0) {
    perror("GETADDR error");
    exit(EXIT_FAILURE);
  }

  /* Create and connect */
  if ((iSockfd = socket(paRes->ai_family, paRes->ai_socktype, paRes->ai_protocol)) < 0) {
    perror("CREATE error");
    exit(EXIT_FAILURE);
  }
  if (connect(iSockfd, paRes->ai_addr, paRes->ai_addrlen) < 0) {
    perror("CONNECT error");
    exit(EXIT_FAILURE);
  }

  /* Free paRes, which was dynamically allocated by getaddrinfo */
  freeaddrinfo(paRes);

  return iSockfd;
}

/* Send message in buf, with length stored in len to the socket with file descriptor sockfd.
 * If there is an error, close sockfd and otherfd. */
static void writeToSocket (const char *buf, int sockfd, int otherfd, int *len) {
	int iSent;
	int iTotalSent = 0;

	while (iTotalSent < *len) {
		if ((iSent = send(sockfd, (void *) (buf + iTotalSent), *len - iTotalSent, 0)) < 0) {
			perror("SEND error");
			shutdown(sockfd, SHUT_RDWR);
			close(sockfd);
			if (otherfd != -1) {
				shutdown(otherfd, SHUT_RDWR);
				close(otherfd);
			}
			exit(EXIT_FAILURE);
		}
		iTotalSent += iSent;
	}
}
/* Receive and return a message from socket with file descriptor sockfd */
static char *readFromClient(int sockfd) {
	enum {BUF_SIZE = 4096};

	int iRecv, iSize;
	int iReqSize = 0;
	char buf[BUF_SIZE + 1];
	char *request;

	/* Allocate memory for request */
	request = (char *) malloc(BUF_SIZE + 1);
	if (request == NULL) {
		writeToSocket(errMessage, sockfd, -1, &errMessageLen);
		shutdown(sockfd, SHUT_RDWR);
		close(sockfd);
		exit(EXIT_FAILURE);
	}
	iSize = BUF_SIZE;
	request[0] = '\0';

	/* Read until request is finished, allocating more memory if necessary */
	while (strstr(request, "\r\n\r\n") == NULL) {
		if ((iRecv = recv(sockfd, buf, BUF_SIZE, 0)) < 0) {
			writeToSocket(errMessage, sockfd, -1, &errMessageLen);
			shutdown(sockfd, SHUT_RDWR);
			close(sockfd);
			exit(EXIT_FAILURE);
		}
		if (iRecv == 0) break;
		buf[iRecv] = '\0';
		iReqSize += iRecv;
		if (iReqSize > iSize) {
			iSize *= 2;
			request = (char *) realloc(request, iSize + 1);
			if (request == NULL) {
				writeToSocket(errMessage, sockfd, -1, &errMessageLen);
				shutdown(sockfd, SHUT_RDWR);
				close(sockfd);
				exit(EXIT_FAILURE);
			}
		}
		strcat(request, buf);
	}

	return request;
}

/* Receive message from socket with file descriptor iServerfd
 * and forward it to socket with file descriptor iClientfd */
static void writeToClient (int iClientfd, int iServerfd) {
	enum {BUF_SIZE = 4096};

	int iRecv;
	char buf[BUF_SIZE];

	while ((iRecv = recv(iServerfd, buf, BUF_SIZE, 0)) > 0)
	      writeToSocket(buf, iClientfd, iServerfd, &iRecv);

	/* Error handling */
	if (iRecv < 0) {
	  writeToSocket(errMessage, iClientfd, iServerfd, &errMessageLen);
	  shutdown(iClientfd, SHUT_RDWR);
	  shutdown(iServerfd, SHUT_RDWR);
	  close(iClientfd);
	  close(iServerfd);
	  exit(EXIT_FAILURE);
	}
}

/* Convert req into a properly formatted request to a server,
 * store the length of the request in reqLen, and return the request.
 * If there is an error, close iClientfd*/
static char *getServerReq (struct ParsedRequest *req, int iClientfd, int *reqLen) {
	int iHeadersLen;
	char *serverReq;
	char *headersBuf;

	/* Set headers */
	ParsedHeader_set(req, "Host", req->host);
	ParsedHeader_set(req, "Connection", "close");

	/* Prepare the headers that the client gave */
	iHeadersLen = ParsedHeader_headersLen(req);
	headersBuf = (char *) malloc(iHeadersLen + 1);
	if (headersBuf == NULL) {
		writeToSocket(errMessage, iClientfd, -1, &errMessageLen);
		shutdown(iClientfd, SHUT_RDWR);
		close(iClientfd);
		exit(EXIT_FAILURE);
	}

	ParsedRequest_unparse_headers(req, headersBuf, iHeadersLen);
	headersBuf[iHeadersLen] = '\0';

	/* Allocate memory for request to server */
	*reqLen = strlen(req->method) + strlen(req->path) + strlen(req->version) + iHeadersLen + 4;
	serverReq = (char *) malloc(*reqLen + 1);
	if (serverReq == NULL) {
		writeToSocket(errMessage, iClientfd, -1, &errMessageLen);
		shutdown(iClientfd, SHUT_RDWR);
		close(iClientfd);
		exit(EXIT_FAILURE);
	}

	/* Build the request */
	serverReq[0] = '\0';
	strcpy(serverReq, req->method);
	strcat(serverReq, " ");
	strcat(serverReq, req->path);
	strcat(serverReq, " ");
	strcat(serverReq, req->version);
	strcat(serverReq, "\r\n");
	strcat(serverReq, headersBuf);

	free(headersBuf);

	return serverReq;
}

/* Handle a request from socket with file descriptor iClientfd. iSockfd is the listening socket. */
static void handleRequest (int iClientfd, int iSockfd) {
	int iPid, iServerfd;
	char *clientReq;
	char *serverReq;

	/* forks child process to deal with request */
	fflush(NULL);
	iPid = fork();
	if (iPid == -1) {
		perror(pcPgmName);
		shutdown(iClientfd, SHUT_RDWR);
		close(iClientfd);
		return;
	}

	if (iPid == 0)
	{
		struct ParsedRequest *req;
		int iReqLen = 0;
		int *reqLen = &iReqLen;

		/* A copy of iSockfd is useless in the child process */
		close(iSockfd);

		clientReq = readFromClient(iClientfd);

		/* Parse client request */
		req = ParsedRequest_create();
		if (ParsedRequest_parse(req, clientReq, strlen(clientReq)) < 0) {
			writeToSocket(errMessage, iClientfd, -1, &errMessageLen);
			shutdown(iClientfd, SHUT_RDWR);
			close(iClientfd);
			exit(EXIT_FAILURE);
		}
		if (req->port == NULL) req->port = (char *) "80";

		/* Act as proxy between client and server */
		serverReq = getServerReq(req, iClientfd, reqLen);
		iServerfd = createClientSocket(req->host, req->port);
		writeToSocket(serverReq, iServerfd, iClientfd, reqLen);
		writeToClient(iClientfd, iServerfd);

		/* Free memory and clean up */
		ParsedRequest_destroy(req);
		free(serverReq);
		free(clientReq);

		shutdown(iClientfd, SHUT_RDWR);
		shutdown(iServerfd, SHUT_RDWR);
		close(iClientfd);
		close(iServerfd);

		exit(EXIT_SUCCESS);
	}

	/* Waits for child processes and updates their number */
	numChild++;
	while (waitpid(-1, NULL, WNOHANG) > 0) {
		numChild--;
	}
	if (numChild >= MAX_NUM_CHILD) {
		wait(NULL);
		numChild--;
	}

	close(iClientfd);
}

/* A web proxy that passes requests and data between multiple web
 * clients and web servers, concurrently*/
int main(int argc, char * argv[]) {
	int iSockfd, iClientfd;
	socklen_t iLen;
	struct sockaddr aClient;

	  /* Single argument of argv[1] is the port number */
	  if (argc != 2) {
	    fprintf(stderr, "Usage: %s <port-number>\n", argv[0]);
	    exit(EXIT_FAILURE);
	  }

	  /* Prepare to process requests */
	  pcPgmName = argv[0];
	  iSockfd = createServerSocket(argv[1]);
	  numChild = 0;
	  iLen = sizeof(struct sockaddr);

	  /* Handle clients */
	  while (1) {
	    /* Accept the client, skipping on failure */
	    if ((iClientfd = accept(iSockfd, &aClient, &iLen)) <=  0) {
	      perror(pcPgmName);
	      shutdown(iClientfd, SHUT_RDWR);
	      close(iClientfd);
	      continue;
	    }
	    handleRequest(iClientfd, iSockfd);
	  }

	  /* Clean up */
	  shutdown(iSockfd, SHUT_RDWR);
	  close(iSockfd);

	  return 0;
}
