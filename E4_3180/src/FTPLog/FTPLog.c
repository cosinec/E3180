#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS
#endif

#define HAVE_REMOTE
#define WIN32 
#include <pcap.h>
#include <Packet32.h>
#include <ntddndis.h>
#include <time.h>
#include <stdio.h>
#include <stdbool.h>
#pragma comment(lib, "Packet")
#pragma comment(lib, "wpcap")
#pragma comment(lib, "WS2_32")

//������
#define FILTER "port 21"

u_char user[20];//�û���
u_char pass[20];//����

//TCP�ײ�
typedef struct tcp_header
{
	u_short sport;//Դ����Ķ˿ں�
	u_short dsport;//Ŀ�ĳ���Ķ˿ں�
	u_int seq;//���к� SN
	u_int ack_num;//ȷ�Ϻ�
	u_char ihl; //Internet ͷ������
	u_char frame;
	u_short wsize;//���ڴ�С
	u_short crc; //check sum
	u_short urg;
}tcp_header;

/* IPv4 �ײ� */
typedef struct ip_header {
	u_char ver_ihl; // Version (4 bits) +Internet header length (4 bits)
	u_char tos; // Type of service
	u_short tlen; // Total length
	u_short identification; // Identification
	u_short flags_fo; // Flags (3 bits) + Fragmentoffset (13 bits)
	u_char ttl; // Time to live
	u_char proto; // Protocol
	u_short crc; // Header checksum
	u_char saddr[4]; // Source address
	u_char daddr[4]; // Destination address
	u_int op_pad; // Option + Padding
} ip_header;

//��̫����֡��ʽ
typedef struct mac_header {
	u_char dest_addr[6];
	u_char src_addr[6];
	u_char type[2];
} mac_header;

//�豸�б�
pcap_if_t* all_devs;

//����ļ�
FILE* fp = NULL;

//��ȡ�豸�����б�
pcap_if_t* getAllDevs() {
	char error[PCAP_ERRBUF_SIZE];
	if (pcap_findalldevs(&all_devs, error) == -1) {
		printf("����: %s\n", error);
		exit(-1);
	}
	return all_devs;
}

//����豸�б������б��ȣ�
int printAllDevs() {
	int DevsCount = 0;
	for (pcap_if_t* d = all_devs; d; d = d->next) {
		printf("%d. %s", ++DevsCount, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}
	return DevsCount;
}

//ѡ���豸�������豸��Ϣ��
pcap_if_t* selectDev(int DevsCount) {
	int choice;
	printf("�������豸���(1-%d):", DevsCount);
	scanf("%d", &choice);

	if (choice <= 0 || choice > DevsCount) {
		printf("�豸��Ӧ��(1-%d)�䣬ʵ������Ϊ%d�����볬�ޣ�\n", DevsCount, choice);
		pcap_freealldevs(all_devs);//�ͷ��豸�б�
		exit(-1);
	}
	pcap_if_t* current_dev;

	//��λ�����豸
	int temp_index = 0;
	for (current_dev = all_devs; temp_index < choice - 1; current_dev = current_dev->next, temp_index++);
	return current_dev;
}

//��ȡ���
pcap_t* getHandle(pcap_if_t* dev) {
	pcap_t* handle;
	char error[PCAP_ERRBUF_SIZE];

	//�򿪽ӿ�
	if ((handle = pcap_open_live(dev->name, 65536, 1, 1000, error)) == NULL) {
		printf("δ�ܴ򿪽ӿ���������WinPcap��֧��%s", dev->name);
		pcap_freealldevs(all_devs);
		exit(-1);
	}

	//����Ƿ�����̫��
	if (pcap_datalink(handle) != DLT_EN10MB) {
		printf("�˳���ֻ����̫�������Ϲ�����\n");
		pcap_freealldevs(all_devs);
		exit(-1);
	}
	return handle;
}

//���ù�����
void setfilter(pcap_t* handle, u_int netmask) {
	struct bpf_program fcode;
	//����������ʽ
	if (pcap_compile(handle, &fcode, FILTER, 1, netmask) < 0) {
		printf("��������ʽ����\n");
		pcap_freealldevs(all_devs);
		exit(-1);
	}

	//���ù�����
	if (pcap_setfilter(handle, &fcode) < 0) {
		printf("���ù�����ʱ����\n");
		pcap_freealldevs(all_devs);
		exit(-1);
	}
}


void output(ip_header* ih, mac_header* mh, const struct pcap_pkthdr* header, char user[], char pass[], bool isSucceed)
{
	if (user[0] == '\0')
		return;

	char timestr[46];
	struct tm* ltime;
	time_t local_tv_sec;

	/*��ʱ���ת���ɿ�ʶ��ĸ�ʽ */
	local_tv_sec = header->ts.tv_sec;
	ltime = localtime(&local_tv_sec);
	strftime(timestr, sizeof timestr, "%Y-%m-%d %H:%M:%S", ltime);
	
	/*���������̨*/
	printf("%s,", timestr);//ʱ��

	// �ӵ�¼�� ftp������ ���ͻ������ص���Ϣ��ȡĿ���ַ��FTP��������ַ����Դ��ַ���ͻ�����ַ��
	printf("%02X-%02X-%02X-%02X-%02X-%02X,",
		mh->dest_addr[0],
		mh->dest_addr[1],
		mh->dest_addr[2],
		mh->dest_addr[3],
		mh->dest_addr[4],
		mh->dest_addr[5]);//�ͻ�����ַ
	printf("%3d.%3d.%3d.%3d,",
		ih->daddr[0],
		ih->daddr[1],
		ih->daddr[2],
		ih->daddr[3]);//�ͻ���IP

	printf("%02X-%02X-%02X-%02X-%02X-%02X,",
		mh->src_addr[0],
		mh->src_addr[1],
		mh->src_addr[2],
		mh->src_addr[3],
		mh->src_addr[4],
		mh->src_addr[5]);//FTP������MAC
	printf("%3d.%3d.%3d.%3d,",
		ih->saddr[0],
		ih->saddr[1],
		ih->saddr[2],
		ih->saddr[3]);//FTP������IP

	printf("%s,%s,", user, pass);//�˺�����

	if (isSucceed) {
		printf("SUCCEED\n");
	}
	else {
		printf("FAILED\n");
	}
	
	/*������ļ�*/
	FILE* fp = fopen("FTPlog.csv", "a+");
	fprintf(fp, "%s,", timestr);//ʱ��

	fprintf(fp, "%02X-%02X-%02X-%02X-%02X-%02X,",
		mh->dest_addr[0],
		mh->dest_addr[1],
		mh->dest_addr[2],
		mh->dest_addr[3],
		mh->dest_addr[4],
		mh->dest_addr[5]);//�ͻ���MAC��ַ
	fprintf(fp, "%3d.%3d.%3d.%3d,",
		ih->daddr[0],
		ih->daddr[1],
		ih->daddr[2],
		ih->daddr[3]);//�ͻ���IP

	fprintf(fp, "%02X-%02X-%02X-%02X-%02X-%02X,",
		mh->src_addr[0],
		mh->src_addr[1],
		mh->src_addr[2],
		mh->src_addr[3],
		mh->src_addr[4],
		mh->src_addr[5]);//FTP������MAC
	fprintf(fp, "%3d.%3d.%3d.%3d,",
		ih->saddr[0],
		ih->saddr[1],
		ih->saddr[2],
		ih->saddr[3]);//FTP������IP

	fprintf(fp, "%s,%s,", user, pass);//�˺�����

	if (isSucceed) {
		fprintf(fp, "SUCCEED\n");
	}
	else {
		fprintf(fp, "FAILED\n");
	}
	fclose(fp);

	user[0] = '\0';
}



/* �ص����������յ�ÿһ�����ݰ�ʱ�ᱻWinpcap������ */
void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data)
{
	ip_header* ih;
	mac_header* mh;
	u_int i = 0;

	int length = sizeof(mac_header) + sizeof(ip_header);
	mh = (mac_header*)pkt_data;
	ih = (ip_header*)(pkt_data + 14); //length ofethernet header

	int name_point = 0;//�û���λ��
	int pass_point = 0;//����λ��
	int tmp;//�ɹ����λ��
	for (int i = 0; i < ih->tlen - 40; i++) {
		//��ȡ�û���
		if (*(pkt_data + i) == 'U' && *(pkt_data + i + 1) == 'S' && *(pkt_data + i + 2) == 'E' && *(pkt_data + i + 3) == 'R') {
			name_point = i + 5;//'u' 's' 'e' 'r' ' '��5���ֽ�,��ת���û�����һ���ֽ�

			//���س�0x0d��ascii 13�����У�ascii 10��Ϊֹ��ǰ����������û���
			int j = 0;
			while (!(*(pkt_data + name_point) == 13 && *(pkt_data + name_point + 1) == 10)) {
				user[j] = *(pkt_data + name_point);//�洢�˺�
				j++;
				++name_point;
			}
			user[j] = '\0';
			break;

		}
		//��ȡ����
		if (*(pkt_data + i) == 'P' && *(pkt_data + i + 1) == 'A' && *(pkt_data + i + 2) == 'S' && *(pkt_data + i + 3) == 'S') {
			pass_point = i + 5;////'P' 'A' 'S' 'S' ' '��5���ֽ�,��ת�������һ���ֽ�
			tmp = pass_point;

			//���س�0x0d��ascii 13�����У�ascii 10��Ϊֹ��ǰ�������������
			int k = 0;
			while (!(*(pkt_data + pass_point) == 13 && *(pkt_data + pass_point + 1) == 10)) {
				pass[k] = *(pkt_data + pass_point);//�洢����
				k++;
				++pass_point;

			}
			pass[k] = '\0';

			for (;; tmp++) {
				//��¼�ɹ�
				if (*(pkt_data + tmp) == '2' && *(pkt_data + tmp + 1) == '3' && *(pkt_data + tmp + 2) == '0') {
					output(ih, mh, header, (char*)user, (char*)pass, true);
					break;
				}
				//��¼ʧ��
				else if (*(pkt_data + tmp) == '5' && *(pkt_data + tmp + 1) == '3' && *(pkt_data + tmp + 2) == '0') {
					output(ih, mh, header, (char*)user, (char*)pass, false);
					break;
				}
			}
			break;
		}
	}
}
//������
int main() {

	//�豸ѡ��
	pcap_if_t* alldevs = getAllDevs();//��ȡ�豸�б�
	int DevsCount = printAllDevs();//����豸�б�

	if (DevsCount == 0) {
		printf("\n����δ����Winpcap\n");
		return -1;
	}

	pcap_if_t* current_dev = selectDev(DevsCount);//ѡ���豸
	//��ȡ���
	pcap_t* handle = getHandle(current_dev);

	//��������
	u_int netmask;
	if (current_dev->addresses != NULL)//��ǰ�豸��ַ��Ϊ����ȡ����
		netmask = ((struct sockaddr_in*)(current_dev->addresses->netmask))->sin_addr.S_un.S_addr;
	else netmask = 0xffffff;//�����豸��C����̫�������У�����Ϊ0xFFFFFF

	//������
	setfilter(handle, netmask);

	//����׼��
	printf("��ʼ����:%s\n", current_dev->description);
	pcap_freealldevs(alldevs);//�ͷ��豸�б�

	//��ʼ����
	pcap_loop(handle, 0, packet_handler, NULL);

	return 0;

}