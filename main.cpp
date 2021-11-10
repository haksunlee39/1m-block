#include "1m-block.h"

#define URI_CHARACTERS 66
#define ALPHABET_SIZE 26

struct TrieNode {
	struct TrieNode *links[URI_CHARACTERS];
	bool isEnd;
};

struct libnet_ipv4_hdr* ipv4Var;
struct libnet_tcp_hdr* tcpVar;

struct TrieNode* root;

void usage() {
	printf("1m-block <site list file>\n");
	printf("1m-block top-1m.txt\n");
}

int charToIndex(char c)
{
	int indexSize = 0;
	if ((int)c >= (int)'a' && (int)c <= (int)'z')
		return (int)c - (int)'a';
		
	indexSize += ALPHABET_SIZE;
		
	if ((int)c >= (int)'A' && (int)c <= (int)'Z')
		return (int)c - (int)'A' + indexSize;
		
	indexSize += ALPHABET_SIZE;
		
	if ((int)c >= (int)'0' && (int)c <= (int)'9')
		return (int)c - (int)'0' + indexSize;
		
	indexSize += 10;
		
	switch(c){
	case '-':
		return indexSize + 0;
	case '_':
		return indexSize + 1;
	case '.':
		return indexSize + 2;
	case '~':
		return indexSize + 3;
	default:
		return -1;
	}
}

struct TrieNode* newNode()
{
	struct TrieNode *temp = NULL;
	
	temp = (struct TrieNode*)malloc(sizeof(struct TrieNode));
	
	temp->isEnd = false;
	
	for(int i = 0; i < URI_CHARACTERS; i++)
		temp->links[i] = NULL;
		
	return temp;
}

void insertIntoTrie(const char* key)
{
	int i;
	int length = strlen(key);
	int index;
	
	struct TrieNode* temp = root;
	
	//printf("%s\n", key);
	
	for (i = 0; i < length; i++)
	{
		index = charToIndex(key[i]);
		//printf("**%d\n", index);
		
		if(!temp->links[index])
			temp->links[index] = newNode();
			
		temp = temp->links[index];
	}
	
	temp->isEnd = true;
}

bool searchInTree(const char* key)
{
	int i;
	int length = strlen(key);
	int index;
	
	struct TrieNode* temp = root;
	
	for(i = 0; i < length; i++)
	{
		index = charToIndex(key[i]);
		if (index == -1)
			return false;
		
		if(!temp->links[index])
			return false;
			
		temp = temp->links[index];
	}
	
	return temp->isEnd;
}

void constructTrie(const char* file)
{	
	printf("%s\n", file);
	FILE *fp = fopen(file, "r");
	char lineBuf[128];
	char tempChar;
	int count = 0;
	int lineCount = 0;
	
	bool isSkipNumber;
	
	printf("%s\n", file);
	
	if (!fp)
	{
		perror("File Error\n");
		exit(1);
	}
	
	root = newNode();
	
	tempChar = getc(fp);
	isSkipNumber = false;
	
	while(tempChar != EOF)
	{
		if(tempChar == '\n')
		{
			lineBuf[count] = '\0';
			insertIntoTrie(lineBuf);
			count = 0;
			tempChar = getc(fp);
			isSkipNumber = false;
			lineCount++;
			
			if (lineCount % 100000 == 0)
				printf("%d\n", lineCount);
			continue;
		}
		else if (!isSkipNumber && tempChar == ',')
		{
			count = 0;
			tempChar = getc(fp);
			isSkipNumber = true;
		}
		lineBuf[count] = tempChar;
		
		tempChar = getc(fp);
		count++;
	}
}

void dump(unsigned char* buf, int size) {
	int i;
	for (i = 0; i < size; i++) {
		if (i != 0 && i % 16 == 0)
			printf("\n");
		printf("%02X ", buf[i]);
	}
	printf("\n");
}

int checkIfHttp(char *payload)
{
	int i, j;
	char keyword[10][10] = {
		"GET",
		"HEAD",
		"POST",
		"PUT",
		"DELETE",
		"CONNECT",
		"OPTIONS",
		"TRACE",
		"PATCH",
		"HTTP"
	};
	
	for (i = 0; i < 10; i++)
	{
		int keywordSize = strlen(keyword[i]);
		for(j = 0; j < keywordSize; j++)
		{
			if (payload[j] != keyword[i][j])
				break;
		}
		
		if (j == keywordSize)
			return 1;
	}
	
	return 0;
}

int checkIfHarmful(char *payload, int size)
{
	int i;
	int hostFieldIndex = 0;
	
	char payloadHost[128];

	for(i = 0; i < size; i++)
	{
		if(strncmp(payload+i, "Host:", 5) == 0)
		{
			hostFieldIndex = i+6;
			break;
		}
	}
	
	if (hostFieldIndex == 0)
		return 0;
	
	i = 1;
	while(payload[hostFieldIndex + i] != 0x0d || payload[hostFieldIndex + i+1] != 0x0a)
	{
		i++;
	}
	
	strncpy(payloadHost, payload+hostFieldIndex, i);
	printf("%s\n", payloadHost);
	
	if(searchInTree(payloadHost))
	{
		printf("Blocked!\n");
		return 1;
	}
		
	return 0;
}


/* returns packet id */
static u_int32_t print_pkt (struct nfq_data *tb)
{
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	u_int32_t mark,ifi;
	int ret;
	unsigned char *data;
	char *payloadData;
	
	u_int32_t ipHeaderLen = 0;
	u_int32_t tcpHeaderLen = 0;

	ph = nfq_get_msg_packet_hdr(tb);
	if (ph) {
		id = ntohl(ph->packet_id);
		//printf("hw_protocol=0x%04x hook=%u id=%u ", ntohs(ph->hw_protocol), ph->hook, id);
	}

	hwph = nfq_get_packet_hw(tb);
	if (hwph) {
		int i, hlen = ntohs(hwph->hw_addrlen);

		//printf("hw_src_addr=");
		//for (i = 0; i < hlen-1; i++)
		//	printf("%02x:", hwph->hw_addr[i]);
		//printf("%02x ", hwph->hw_addr[hlen-1]);
	}

	ret = nfq_get_payload(tb, &data);
	if (ret >= 0){
		//printf("payload_len=%d\n", ret);
		//dump(data, ret);
	}

	//fputc('\n', stdout);
	
	ipv4Var = (struct libnet_ipv4_hdr*)(data);
	if (ipv4Var->ip_p != 0x06) return id;
	ipHeaderLen = ipv4Var->ip_hl * 4;
	tcpVar = (struct libnet_tcp_hdr*)(data + ipHeaderLen);
	tcpHeaderLen = tcpVar->th_off * 4;
	payloadData = (char*)(data + ipHeaderLen  + tcpHeaderLen);
	
	if (checkIfHttp(payloadData) && checkIfHarmful(payloadData, ret-ipHeaderLen - tcpHeaderLen))
	{
		id *= -1;
	}

	return id;
}


static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *data)
{
	u_int32_t id = print_pkt(nfa);
	//printf("entering callback\n");
	return nfq_set_verdict(qh, id < 0 ? id*-1:id, id < 0 ? NF_DROP:NF_ACCEPT, 0, NULL);
}

int main(int argc, char **argv)
{
	if(argc != 2)
	{
		usage();
		return -1;
	}
	
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
	struct TrieNode* trieRoot;
	int fd;
	int rv;
	char buf[4096] __attribute__ ((aligned));
	
	constructTrie(argv[1]);

	printf("opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("binding this socket to queue '0'\n");
	qh = nfq_create_queue(h,  0, &cb, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	fd = nfq_fd(h);

	for (;;) {
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
			//printf("pkt received\n");
			nfq_handle_packet(h, buf, rv);
			continue;
		}
		/* if your application is too slow to digest the packets that
		 * are sent from kernel-space, the socket buffer that we use
		 * to enqueue packets may fill up returning ENOBUFS. Depending
		 * on your application, this error may be ignored. nfq_nlmsg_verdict_putPlease, see
		 * the doxygen documentation of this library on how to improve
		 * this situation.
		 */
		if (rv < 0 && errno == ENOBUFS) {
			printf("losing packets!\n");
			continue;
		}
		perror("recv failed");
		break;
	}

	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h);

	exit(0);
}

