#ifndef __ILIFESWEEPER_H__
#define __ILIFESWEEPER_H__

#define SendMAXLen (64)
#define RecvMAXLen (1024 + 8)

/************串口通信命令宏定义***************/
#define UartNOP  	(0)           /*  串口接收错误或空闲	*/
#define UartSOP  	(1)           /*  接收起始位		*/
#define UartLEN_H  	(2)           /*  接收长度			*/
#define UartLEN_L  	(3)           /*  接收长度			*/
#define UartRESV_H	(4)			  /*  保留位1			*/
#define UartRESV_L	(5)			  /*  保留位2			*/
#define UartCMD  	(6)           /*  接收命令			*/
#define UartDATA 	(7)           /*  接收数据			*/
#define UartCRC  	(8)           /*  数据长度为0 		*/
#define UartEND  	(9)           /*  接收结束标志*/

//串口帧结构定义
#define F_HEAD  (0x5A)	//帧头
#define F_END   (0x5B)	//帧尾

/* 发送失败重发次数定义和发送时间间隔定义 */
#define SENDDELAYTIME (5)	/* 5ms检查一次 */
#define SENDGAPTIME (160)	/* 160 * 5ms = 800ms */
#define SENDCNT		(318)	/* 发送318*5ms=1590ms左右还没有回复，发送超时，退出 */

//命令值定义:
#define CMDRequeryDeviceStatus 	(0x41)
#define CMDRequeryTimerInfo		(0x42)
#define CMDRequeryLifeTime		(0x44)
#define CMDRequeryFWVersion	(0x45)
//测试用添加
#define CMDRequeryMACAddr		(0xA1)	//获取mac地址
#define CMDRequerySWVersion	(0xA2)	//获取8711am软件版本

#define CMDDownWorkMode 		(0x46)
#define CMDDownRoomMode 		(0x47)
#define CMDDownCleanStrength 	(0x48)
#define CMDDownControl			(0x49)
#define CMDDownTimer			(0x4A)
#define CMDDownReset			(0x4B)
#define CMDDownCalTime			(0x4C)
#define CMDDownupRealtimeInfo	(0x4D)
#define CMDDownDisturb			(0x4E)
#define CMDDownFactoryReset	(0x4F)
#define CMDDownSearch			(0x50)

#define CMDUpLoadStatus			(0xC8)
#define CMDUpLoadCleanRecord	(0xC9)
#define CMDUpLoadMapInfo		(0xCA)
#define CMDUpLoadSumTime		(0xCB)
#define CMDUpLoadFactoryReset	(0xCC)
#define CMDUpLoadCleanMapInfo	(0xCD)
#define CMDUpLoadLifeTime		(0xCE)
#define CMDUpLoadAppointmentInfo	(0xCF)
#define CMDUpLoadReset			(0xD0)
#define CMDUpLoadSearch		(0xD1)
#define CMDUpLoadControl		(0xD2)
#define CMDUpLoadFWVersion		(0xD3)
#define CMDUpLoadRealTimeStart 	(0xD4)
#define CMDUpLoadRealInfoSwitch (0xD5)

#define CMDSysNetWorking		(0x02)
#define CMDSysNetBroken			(0x03)
#define CMDSysCloudWorking		(0x04)
#define CMDSysCloudBroken		(0x05)
#define CMDSysConfNetWork		(0x08)
#define CMDSysQueryNTP			(0x0D)
#define CMDSysGetSigQuality		(0x0E)

/* 发送循环buffer */
#define SENDBUFFERMAXLEN (10)	/* 定义发送循环buffer的大小 */
struct RingSendBuffer_t{
	unsigned short Length;		/* Data数据的长度 */
	unsigned char Data[SendMAXLen];	/* 缓冲数据实体，包含一帧数据的CMD字段和数据字段 */
};

/* 接收循环buffer */
#define RECVBUFFERMAXLEN (10)	/* 定义发送循环buffer的大小 */
struct RingRecvBuffer_t{
	unsigned short Length;		/* Data数据的长度 */
	unsigned char CMD;
	unsigned char Data[RecvMAXLen];	/* 缓冲数据实体，包含一帧数据的CMD字段和数据字段 */
};

extern struct RingSendBuffer_t RingSendBuffer[SENDBUFFERMAXLEN];


//属性变量
//to device
extern int t_work_mode;
extern int t_room_mode;
extern int t_d_strength;
extern int t_p_strength;
extern int t_control;
extern unsigned char t_search;
extern unsigned char t_reset_edge_brush;
extern unsigned char t_reset_roll_brush;
extern unsigned char t_reset_filter;
extern unsigned char t_reset_duster;
extern unsigned char t_reset_power;
extern unsigned char t_sound;
extern unsigned char t_light;
extern unsigned char t_factory_reset;
extern unsigned char t_realtime_info; 				//下发上传实时信息

extern unsigned char t_timer_0[11];
extern unsigned char t_timer_1[11];
extern unsigned char t_timer_2[11];
extern unsigned char t_timer_3[11];
extern unsigned char t_timer_4[11];
extern unsigned char t_timer_5[11];
extern unsigned char t_timer_6[11];
extern unsigned char t_timer_7[11];
extern unsigned char t_timer_8[11];
extern unsigned char t_timer_9[11];

//from device
extern int f_clean_mode;
extern int f_battery;
extern int ff_error;
extern int f_edge_brush_lifetime;
extern int f_roll_brush_lifetime;
extern int f_filter_lifetime;
extern int f_duster_lifetime;
extern int f_battery_lifetime;
extern int f_work_time;
extern int f_water_box_time;
extern int f_dustbin_time;
extern int f_mul_box_time;
extern unsigned char f_clean_record[17];
extern unsigned char f_upload_realmap_switch;
extern unsigned char f_upload_realmap_starttime[17];
extern unsigned char f_realtime_mapinfo[686];

/* 临时属性变量 */
extern unsigned char f_clean_record_temp[17];
extern unsigned char t_timer_temp[11];

/* 网络接口定义 */
extern struct netif xnetif[NET_IF_NUM]; 

void WriteRingBuffer(unsigned char *Data, unsigned short Len);
void ILIFESweeperInit(void);
void PRINTFSendBuffer(const unsigned char *SendFormData, unsigned short Len);
void prop_send_by_name(const char *name);

/* 系统属性 */
extern char version_temp[];
extern char version[64];
extern char MCUFWversion[12];
extern char demo_host_version[];	/* property template version */

/* 系统指令和查询指令 */
void RequeryDeviceStatus(void);
void RequeryTimerInfo(void);
void RequeryLifeTime(void);
void RequeryFWVersion(void);

void SendNetWorkStatus(unsigned char NetConnetFlag);
void SendCloudStatus(unsigned char CloudStatus);

void releasewakelock(void);
void acquirewakelock(void);
void sysreleasewakelock(void);


#endif

