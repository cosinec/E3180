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

//过滤器
#define FILTER "port 21"

u_char user[20];//用户名
u_char pass[20];//密码

//TCP首部
typedef struct tcp_header
{
	u_short sport;//源程序的端口号
	u_short dsport;//目的程序的端口号
	u_int seq;//序列号 SN
	u_int ack_num;//确认号
	u_char ihl; //Internet 头部长度
	u_char frame;
	u_short wsize;//窗口大小
	u_short crc; //check sum
	u_short urg;
}tcp_header;

/* IPv4 首部 */
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

//以太网的帧格式
typedef struct mac_header {
	u_char dest_addr[6];
	u_char src_addr[6];
	u_char type[2];
} mac_header;

//设备列表
pcap_if_t* all_devs;

//输出文件
FILE* fp = NULL;

//获取设备网卡列表
pcap_if_t* getAllDevs() {
	char error[PCAP_ERRBUF_SIZE];
	if (pcap_findalldevs(&all_devs, error) == -1) {
		printf("错误: %s\n", error);
		exit(-1);
	}
	return all_devs;
}

//输出设备列表（返回列表长度）
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

//选择设备（返回设备信息）
pcap_if_t* selectDev(int DevsCount) {
	int choice;
	printf("请输入设备序号(1-%d):", DevsCount);
	scanf("%d", &choice);

	if (choice <= 0 || choice > DevsCount) {
		printf("设备号应在(1-%d)间，实际输入为%d，输入超限！\n", DevsCount, choice);
		pcap_freealldevs(all_devs);//释放设备列表
		exit(-1);
	}
	pcap_if_t* current_dev;

	//定位到该设备
	int temp_index = 0;
	for (current_dev = all_devs; temp_index < choice - 1; current_dev = current_dev->next, temp_index++);
	return current_dev;
}

//获取句柄
pcap_t* getHandle(pcap_if_t* dev) {
	pcap_t* handle;
	char error[PCAP_ERRBUF_SIZE];

	//打开接口
	if ((handle = pcap_open_live(dev->name, 65536, 1, 1000, error)) == NULL) {
		printf("未能打开接口适配器，WinPcap不支持%s", dev->name);
		pcap_freealldevs(all_devs);
		exit(-1);
	}

	//检查是否在以太网
	if (pcap_datalink(handle) != DLT_EN10MB) {
		printf("此程序只在以太网网络上工作！\n");
		pcap_freealldevs(all_devs);
		exit(-1);
	}
	return handle;
}

//设置过滤器
void setfilter(pcap_t* handle, u_int netmask) {
	struct bpf_program fcode;
	//检查过滤器格式
	if (pcap_compile(handle, &fcode, FILTER, 1, netmask) < 0) {
		printf("过滤器格式错误！\n");
		pcap_freealldevs(all_devs);
		exit(-1);
	}

	//设置过滤器
	if (pcap_setfilter(handle, &fcode) < 0) {
		printf("设置过滤器时出错！\n");
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

	/*将时间戳转换成可识别的格式 */
	local_tv_sec = header->ts.tv_sec;
	ltime = localtime(&local_tv_sec);
	strftime(timestr, sizeof timestr, "%Y-%m-%d %H:%M:%S", ltime);
	
	/*输出到控制台*/
	printf("%s,", timestr);//时间

	// 从登录后 ftp服务器 给客户机返回的信息提取目标地址（FTP服务器地址）和源地址（客户机地址）
	printf("%02X-%02X-%02X-%02X-%02X-%02X,",
		mh->dest_addr[0],
		mh->dest_addr[1],
		mh->dest_addr[2],
		mh->dest_addr[3],
		mh->dest_addr[4],
		mh->dest_addr[5]);//客户机地址
	printf("%3d.%3d.%3d.%3d,",
		ih->daddr[0],
		ih->daddr[1],
		ih->daddr[2],
		ih->daddr[3]);//客户机IP

	printf("%02X-%02X-%02X-%02X-%02X-%02X,",
		mh->src_addr[0],
		mh->src_addr[1],
		mh->src_addr[2],
		mh->src_addr[3],
		mh->src_addr[4],
		mh->src_addr[5]);//FTP服务器MAC
	printf("%3d.%3d.%3d.%3d,",
		ih->saddr[0],
		ih->saddr[1],
		ih->saddr[2],
		ih->saddr[3]);//FTP服务器IP

	printf("%s,%s,", user, pass);//账号密码

	if (isSucceed) {
		printf("SUCCEED\n");
	}
	else {
		printf("FAILED\n");
	}
	
	/*输出到文件*/
	FILE* fp = fopen("FTPlog.csv", "a+");
	fprintf(fp, "%s,", timestr);//时间

	fprintf(fp, "%02X-%02X-%02X-%02X-%02X-%02X,",
		mh->dest_addr[0],
		mh->dest_addr[1],
		mh->dest_addr[2],
		mh->dest_addr[3],
		mh->dest_addr[4],
		mh->dest_addr[5]);//客户机MAC地址
	fprintf(fp, "%3d.%3d.%3d.%3d,",
		ih->daddr[0],
		ih->daddr[1],
		ih->daddr[2],
		ih->daddr[3]);//客户机IP

	fprintf(fp, "%02X-%02X-%02X-%02X-%02X-%02X,",
		mh->src_addr[0],
		mh->src_addr[1],
		mh->src_addr[2],
		mh->src_addr[3],
		mh->src_addr[4],
		mh->src_addr[5]);//FTP服务器MAC
	fprintf(fp, "%3d.%3d.%3d.%3d,",
		ih->saddr[0],
		ih->saddr[1],
		ih->saddr[2],
		ih->saddr[3]);//FTP服务器IP

	fprintf(fp, "%s,%s,", user, pass);//账号密码

	if (isSucceed) {
		fprintf(fp, "SUCCEED\n");
	}
	else {
		fprintf(fp, "FAILED\n");
	}
	fclose(fp);

	user[0] = '\0';
}



/* 回调函数，当收到每一个数据包时会被Winpcap所调用 */
void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data)
{
	ip_header* ih;
	mac_header* mh;
	u_int i = 0;

	int length = sizeof(mac_header) + sizeof(ip_header);
	mh = (mac_header*)pkt_data;
	ih = (ip_header*)(pkt_data + 14); //length ofethernet header

	int name_point = 0;//用户名位置
	int pass_point = 0;//密码位置
	int tmp;//成功与否位置
	for (int i = 0; i < ih->tlen - 40; i++) {
		//获取用户名
		if (*(pkt_data + i) == 'U' && *(pkt_data + i + 1) == 'S' && *(pkt_data + i + 2) == 'E' && *(pkt_data + i + 3) == 'R') {
			name_point = i + 5;//'u' 's' 'e' 'r' ' '共5个字节,跳转至用户名第一个字节

			//到回车0x0d（ascii 13）换行（ascii 10）为止，前面的内容是用户名
			int j = 0;
			while (!(*(pkt_data + name_point) == 13 && *(pkt_data + name_point + 1) == 10)) {
				user[j] = *(pkt_data + name_point);//存储账号
				j++;
				++name_point;
			}
			user[j] = '\0';
			break;

		}
		//获取密码
		if (*(pkt_data + i) == 'P' && *(pkt_data + i + 1) == 'A' && *(pkt_data + i + 2) == 'S' && *(pkt_data + i + 3) == 'S') {
			pass_point = i + 5;////'P' 'A' 'S' 'S' ' '共5个字节,跳转至密码第一个字节
			tmp = pass_point;

			//到回车0x0d（ascii 13）换行（ascii 10）为止，前面的内容是密码
			int k = 0;
			while (!(*(pkt_data + pass_point) == 13 && *(pkt_data + pass_point + 1) == 10)) {
				pass[k] = *(pkt_data + pass_point);//存储密码
				k++;
				++pass_point;

			}
			pass[k] = '\0';

			for (;; tmp++) {
				//登录成功
				if (*(pkt_data + tmp) == '2' && *(pkt_data + tmp + 1) == '3' && *(pkt_data + tmp + 2) == '0') {
					output(ih, mh, header, (char*)user, (char*)pass, true);
					break;
				}
				//登录失败
				else if (*(pkt_data + tmp) == '5' && *(pkt_data + tmp + 1) == '3' && *(pkt_data + tmp + 2) == '0') {
					output(ih, mh, header, (char*)user, (char*)pass, false);
					break;
				}
			}
			break;
		}
	}
}
//主函数
int main() {

	//设备选择
	pcap_if_t* alldevs = getAllDevs();//获取设备列表
	int DevsCount = printAllDevs();//输出设备列表

	if (DevsCount == 0) {
		printf("\n错误，未发现Winpcap\n");
		return -1;
	}

	pcap_if_t* current_dev = selectDev(DevsCount);//选择设备
	//获取句柄
	pcap_t* handle = getHandle(current_dev);

	//设置掩码
	u_int netmask;
	if (current_dev->addresses != NULL)//当前设备地址不为空则取掩码
		netmask = ((struct sockaddr_in*)(current_dev->addresses->netmask))->sin_addr.S_un.S_addr;
	else netmask = 0xffffff;//假设设备在C类以太网上运行，掩码为0xFFFFFF

	//过滤器
	setfilter(handle, netmask);

	//监听准备
	printf("开始监听:%s\n", current_dev->description);
	pcap_freealldevs(alldevs);//释放设备列表

	//开始监听
	pcap_loop(handle, 0, packet_handler, NULL);

	return 0;

}