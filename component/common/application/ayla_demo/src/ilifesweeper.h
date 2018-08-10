#ifndef __ILIFESWEEPER_H__
#define __ILIFESWEEPER_H__

#define SendMAXLen 		(64)
#define RecvMAXLen 		(1024 + 8)

/************����ͨ������궨��***************/
#define UartNOP  		(0)           /*  ���ڽ��մ�������	*/
#define UartSOP  		(1)           /*  ������ʼλ		*/
#define UartLEN_H  	(2)           /*  ���ճ���			*/
#define UartLEN_L  	(3)           /*  ���ճ���			*/
#define UartRESV_H	(4)			  /*  ����λ1			*/
#define UartRESV_L	(5)			  /*  ����λ2			*/
#define UartCMD  		(6)           /*  ��������			*/
#define UartDATA 		(7)           /*  ��������			*/
#define UartCRC  		(8)           /*  ���ݳ���Ϊ0 		*/
#define UartEND  		(9)           /*  ���ս�����־*/

//����֡�ṹ����
#define F_HEAD  		(0x5A)	//֡ͷ
#define F_END  		(0x5B)	//֡β

/* ����ʧ���ط���������ͷ���ʱ�������� */
#define SENDDELAYTIME 		(5)	/* 5ms���һ�� */
#define SENDGAPTIME 			(400)	/* 160 * 5ms = 800ms */
#define SENDCNT				(796)	/* ����318*5ms=1590ms���һ�û�лظ������ͳ�ʱ���˳� */

//����ֵ����:
#define CMDRequeryDeviceStatus 	(0x41)
#define CMDRequeryTimerInfo		(0x42)
#define CMDRequeryLifeTime		(0x44)
#define CMDRequeryFWVersion		(0x45)
//���������
#define CMDRequeryMACAddr		(0xA1)	//��ȡmac��ַ
#define CMDRequerySWVersion		(0xA2)	//��ȡ8711am����汾

#define CMDDownWorkMode 		(0x46)
#define CMDDownRoomMode 		(0x47)
#define CMDDownCleanStrength 		(0x48)
#define CMDDownControl			(0x49)
#define CMDDownTimer			(0x4A)
#define CMDDownReset			(0x4B)
#define CMDDownCalTime			(0x4C)
#define CMDDownupRealtimeInfo	(0x4D)
#define CMDDownDisturb			(0x4E)
#define CMDDownFactoryReset		(0x4F)
#define CMDDownSearch			(0x50)

#define CMDUpLoadStatus			(0xC8)
#define CMDUpLoadCleanRecord		(0xC9)
#define CMDUpLoadMapInfo		(0xCA)
#define CMDUpLoadSumTime		(0xCB)
#define CMDUpLoadFactoryReset	(0xCC)
#define CMDUpLoadCleanMapInfo	(0xCD)
#define CMDUpLoadLifeTime		(0xCE)
#define CMDUpLoadAppointmentInfo	(0xCF)
#define CMDUpLoadReset			(0xD0)
#define CMDUpLoadSearch			(0xD1)
#define CMDUpLoadControl			(0xD2)
#define CMDUpLoadFWVersion		(0xD3)
#define CMDUpLoadRealTimeStart 	(0xD4)
#define CMDUpLoadRealInfoSwitch 	(0xD5)

#define CMDSysNetWorking			(0x02)
#define CMDSysNetBroken			(0x03)
#define CMDSysCloudWorking		(0x04)
#define CMDSysCloudBroken		(0x05)
#define CMDSysConfNetWork		(0x08)
#define CMDSysQueryNTP			(0x0D)
#define CMDSysGetSigQuality		(0x0E)

/* ����ѭ��buffer */
#define SENDBUFFERMAXLEN (10)	/* ���巢��ѭ��buffer�Ĵ�С */
struct RingSendBuffer_t{
	unsigned short Length;		/* Data���ݵĳ��� */
	unsigned char Data[SendMAXLen];	/* ��������ʵ�壬����һ֡���ݵ�CMD�ֶκ������ֶ� */
};

/* ����ѭ��buffer */
#define RECVBUFFERMAXLEN (10)	/* ���巢��ѭ��buffer�Ĵ�С */
struct RingRecvBuffer_t{
	unsigned short Length;		/* Data���ݵĳ��� */
	unsigned char CMD;
	unsigned char Data[RecvMAXLen];	/* ��������ʵ�壬����һ֡���ݵ�CMD�ֶκ������ֶ� */
};

//extern struct RingSendBuffer_t RingSendBuffer[SENDBUFFERMAXLEN];	/*û�����������ļ�ʹ��������������Բ��������� */


//���Ա���
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
extern unsigned char t_realtime_info; 				//�·��ϴ�ʵʱ��Ϣ

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

/* ��ʱ���Ա��� */
extern unsigned char f_clean_record_temp[17];
extern unsigned char t_timer_temp[11];

/* ����ӿڶ��� */
extern struct netif xnetif[NET_IF_NUM]; 

/* ϵͳ���� */
extern char version_temp[];
extern char version[64];
extern char MCUFWversion[12];
extern char demo_host_version[];

/* �������Ե�λ�� */
enum PropPost {
	PP_oem_host_version,
	PP_version,
	PP_t_work_mode,
	PP_t_room_mode,
	PP_t_control,
	PP_t_search,
	PP_t_factory_reset,
	PP_t_realtime_info,
	PP_t_d_strength,
	PP_t_p_strength,
	PP_t_sound,
	PP_t_light,
	PP_t_reset_edge_brush,
	PP_t_reset_roll_brush,
	PP_t_reset_filter,
	PP_t_reset_duster,
	PP_t_reset_power,
	PP_t_timer_0,
	PP_t_timer_1,
	PP_t_timer_2,
	PP_t_timer_3,
	PP_t_timer_4,
	PP_t_timer_5,
	PP_t_timer_6,
	PP_t_timer_7,
	PP_t_timer_8,
	PP_t_timer_9,
	PP_f_clean_mode,
	PP_f_battery,
	PP_f_error,
	PP_f_edge_brush_lifetime,
	PP_f_roll_brush_lifetime,
	PP_f_filter_lifetime,
	PP_f_duster_lifetime,
	PP_f_battery_lifetime,
	PP_f_work_time,
	PP_f_water_box_time,
	PP_f_dustbin_time,
	PP_f_mul_box_time,
	PP_f_upload_realmap_switch,
	PP_f_clean_record,
	PP_f_upload_realmap_starttime,
	PP_f_realtime_mapinfo
};

#endif

