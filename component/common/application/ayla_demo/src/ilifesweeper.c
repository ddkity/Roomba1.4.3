//#define HAVE_UTYPES
//#include "lwip/ip_addr.h"
//#include <ayla/utypes.h>
//#include <sys/types.h>
//#include <ada/libada.h>
//#include <ada/sprop.h>
//#include <ada/task_label.h>
//#include "freertos_pmu.h"
//#include "gpio_irq_api.h"

#include <sys/types.h>
#include <ayla/utypes.h>
#include <ayla/clock.h>
#include "lwip_netconf.h"

#include "FreeRTOS.h"
#include "task.h"
#include "semphr.h" 
#include "freertos_pmu.h"

#include "serial_api.h"
#include "timer_api.h"
#include "gpio_irq_api.h"
#include "ilifesweeper.h"

/*
 * Log message severity prefix.
 */
#define LOG_INFO_RF	"\x81"
#define LOG_WARN_RF	"\x82"
#define LOG_ERR_RF		"\x83"
#define LOG_DEBUG_RF	"\x84"
#define LOG_FAIL_RF	"\x85"
#define LOG_PASS_RF	"\x86"
#define LOG_METRIC_RF	"\x87"
#define LOG_DEBUG2_RF	"\x89"
#define LOG_BASE_RF	0x80

/* 定义循环发送buffer */
SECTION(".sdram.data") struct RingSendBuffer_t RingSendBuffer[SENDBUFFERMAXLEN] = {0};
SECTION(".sdram.data") unsigned char R_CurSor = 0;	/* 读位置 */
SECTION(".sdram.data") unsigned char W_CurSor = 0;	/* 写位置 */
SECTION(".sdram.data") unsigned char DataNum = 0;	/* 环形缓存区中的元素总数量 */
/* 定义接收循环buffer */
SECTION(".sdram.data") struct RingRecvBuffer_t RingRecvBuffer[RECVBUFFERMAXLEN] = {0};
SECTION(".sdram.data") unsigned char R_CurSorRecv = 0;	/* 读位置 */
SECTION(".sdram.data") unsigned char W_CurSorRecv = 0;	/* 写位置 */
SECTION(".sdram.data") unsigned char DataNumRecv = 0;	/* 环形缓存区中的元素总数量 */

serial_t sobj;
gtimer_t SweeperTimer;
#define UART_TX    PA_7
#define UART_RX    PA_6

SECTION(".sdram.data") unsigned char RecvCharTemp = 0;
SECTION(".sdram.data") unsigned char UartStatus = UartNOP;
SECTION(".sdram.data") unsigned char UartRxOkFlag = 0;
SECTION(".sdram.data") unsigned char RecvBuffer[RecvMAXLen] = {0};
SECTION(".sdram.data") unsigned short UartRecvLen = 0;
SECTION(".sdram.data") unsigned short UartDataLen = 0;		/* 数据包中整个数据包的长度（包括包头、包长度、 包长度、 保留位、 保留位、功能码、数据、校验和、包尾） */
SECTION(".sdram.data") unsigned char CalCRC = 0;	/* 计算出来的CRC数据 */
SECTION(".sdram.data") unsigned char RecvCRC = 0;	/* 接收到的CRC数据 */
SECTION(".sdram.data") unsigned char UartIrqRecvTimeOut = 0;	/* 串口中断接收超时标志，防止发送错误数据的时候影响下一帧的接收 */

/* 串口发送时单片机的回复命令 */
SECTION(".sdram.data") unsigned char SendRespondCMD = 0x00;

/* 进入低功耗标志位,用于检测唤醒多少秒之后没有进入低功耗的，则自动进入低功耗 */
SECTION(".sdram.data") unsigned char AutoEnterLowpower = 0;

/* base64编码 */
int ilife_ayla_base64_encode(const void *in_buf, size_t inlen,
			void *out, size_t *outlen)
{
	unsigned long i, len2, leven;
	const unsigned char *in = in_buf;
	unsigned char *p;
	static const char *codes =
	    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

	/* valid output size ? */
	len2 = 4 * ((inlen + 2) / 3);
	log_put(LOG_INFO_RF "*outlen = %d, len2 = %d", *outlen, len2);
	if (*outlen < len2 + 1) {
		return -1;
	}
	p = out;
	leven = 3 * (inlen / 3);
	for (i = 0; i < leven; i += 3) {
		*p++ = codes[(in[0] >> 2) & 0x3F];
		*p++ = codes[(((in[0] & 3) << 4) + (in[1] >> 4)) & 0x3F];
		*p++ = codes[(((in[1] & 0xf) << 2) + (in[2] >> 6)) & 0x3F];
		*p++ = codes[in[2] & 0x3F];
		in += 3;
	}
	/* Pad it if necessary...  */
	if (i < inlen) {
		unsigned a = in[0];
		unsigned b = (i + 1 < inlen) ? in[1] : 0;

		*p++ = codes[(a >> 2) & 0x3F];
		*p++ = codes[(((a & 3) << 4) + (b >> 4)) & 0x3F];
		*p++ = (i + 1 < inlen) ? codes[(((b & 0xf) << 2)) & 0x3F] : '=';
		*p++ = '=';
	}

	/* append a NULL byte */
	*p = '\0';

	/* return ok */
	*outlen = p - (unsigned char *)out;
	return 0;
}
/* SendFormData包括CMD和Data字段, len的长度是SendFormData的长度 */
void UartSendFormData(const unsigned char *SendFormData, unsigned short Len)
{
	unsigned char SendDataTem[SendMAXLen + 7] = {0};
	unsigned short SendDataLen = 0;
	unsigned char CRCTem = 0;
	unsigned short i;
	
	SendDataTem[SendDataLen++] = F_HEAD;					//包头
	SendDataTem[SendDataLen++] = ((Len + 7)>>8) & 0xFF;		//包长高8位
	CRCTem += SendDataTem[SendDataLen - 1];
	SendDataTem[SendDataLen++] = ((Len + 7)>>0) & 0xFF;		//包长低八位
	CRCTem += SendDataTem[SendDataLen - 1];
	
	SendDataTem[SendDataLen++] = 0x00;						//保留位
	CRCTem += SendDataTem[SendDataLen - 1];
	SendDataTem[SendDataLen++] = 0x00;						//保留位
	CRCTem += SendDataTem[SendDataLen - 1];
	
	SendDataTem[SendDataLen++] = SendFormData[0];			//功能码
	CRCTem += SendDataTem[SendDataLen - 1];

	for(i = 0; i < Len - 1; i++){
		SendDataTem[SendDataLen++] = SendFormData[i + 1];	//数据
		CRCTem += SendDataTem[SendDataLen - 1];
	}

	SendDataTem[SendDataLen++] = CRCTem;					//校验和
	SendDataTem[SendDataLen++] = F_END;						//包尾

	//开始发送数据
	printf("Send Data:");
	for(i = 0; i < SendDataLen; i++)
	{
		printf("%02x ", SendDataTem[i]);
	}
	printf("\n");
	
	for(i = 0; i < SendDataLen; i++)
	{
		serial_putc(&sobj, SendDataTem[i]);
	}
}


/* 擦除模组]wifi信息 */
void ForceWifiErase(void)
{
	int i = 0;
	
	vTaskDelay(1000);	//1s
	for(i = 0; i < 11; i++)
	{
		adw_wifi_profile_erase(i);
		vTaskDelay(50);
	}
	
	conf_save_config();
	log_put(LOG_INFO_RF "Wifi erase ok.\n");
	vTaskDelay(2000);
	ada_conf_reset(0);
}

void SendSysNTP(struct clock_info clk, unsigned int NTP_utc)
{
	unsigned char Data[13];

	Data[0] = CMDSysQueryNTP;

	//年
	Data[1] = (clk.year >> 8) & 0xFF;
	Data[2] = clk.year & 0xFF;
	//月
	Data[3] = clk.month;
	//日
	Data[4] = clk.days;
	//星期
	Data[5] = clk.day_of_week;
	//时
	Data[6] = clk.hour;
	//分
	Data[7] = clk.min;
	//秒
	Data[8] = clk.sec;
	//NTP秒数
	Data[9] = (NTP_utc >> 24) & 0xFF;
	Data[10] = (NTP_utc >> 16) & 0xFF;
	Data[11] = (NTP_utc >> 8) & 0xFF;
	Data[12] = (NTP_utc >> 0) & 0xFF;

	UartSendFormData(Data, 13);
}

void SendWifiSignal(unsigned char Signal)
{
	unsigned char Data[2];

	Data[0] = CMDSysGetSigQuality;
	if(Signal == 0){
		Data[1] = 0;
	}else{
		Data[1] = 100 - Signal;
	}

	UartSendFormData(Data, 2);
}

/*************************************************************************************
*	串口接收数据处理，传进来的数据包括帧头帧尾的一整帧数据 
*************************************************************************************/
void ProtocalUartData(unsigned char CMD, unsigned char *Data, unsigned short Length)
{
	int i;
	int VersionLen = 0; 
	unsigned int MapDataLen_encode = 686;
	unsigned char AckSendData[10] = {0};	/* 返回单片机的Data */
	static unsigned char CMDUpLoadAppointmentInfoChange = 0;
	
	struct clock_info clk;
	unsigned int LocalToUTCtime;
	unsigned int NTP_utc = 0;	//utc时间
	unsigned int NTP_local = 0;	//本地时间
	
	int WifiSignal;				//WIFI的信号质量
	
	unsigned char *mac;

	printf("Recv Data:");
	for(i = 0; i < Length; i++)
	{
		printf("%02x ", Data[i]);
	}
	printf("\n");

	switch(CMD)
	{
		//上传指令
		case CMDUpLoadStatus:
			t_work_mode = Data[6];
			prop_send_by_name("t_work_mode", PP_t_work_mode);

			if(t_room_mode != Data[7]){
				t_room_mode = Data[7];
				prop_send_by_name("t_room_mode", PP_t_room_mode);
			}

			if(f_clean_mode != Data[8]){
				f_clean_mode = Data[8];
				prop_send_by_name("f_clean_mode", PP_f_clean_mode);
			}

			if(t_d_strength != Data[9]){
				t_d_strength = Data[9];
				prop_send_by_name("t_d_strength", PP_t_d_strength);
			}

			if(t_p_strength != Data[10]){
				t_p_strength = Data[10];
				prop_send_by_name("t_p_strength", PP_t_p_strength);
			}

			if(f_battery != Data[11]){
				f_battery = Data[11];
				prop_send_by_name("f_battery", PP_f_battery);
			}

			if(t_sound != Data[12]){
				t_sound = Data[12];
				prop_send_by_name("t_sound", PP_t_sound);
			}

			if(t_light != Data[13]){
				t_light = Data[13];
				prop_send_by_name("t_light", PP_t_light);
			}

			if(ff_error != Data[14]){
				ff_error = Data[14];
				prop_send_by_name("f_error", PP_f_error);
			}
			
			AckSendData[0] = CMD;
			AckSendData[1] = 0x00;
			UartSendFormData(AckSendData, 2);
			break;

		case CMDUpLoadCleanRecord:
			
			sprintf(&f_clean_record_temp[0], "%02x", Data[6]);
			sprintf(&f_clean_record_temp[2], "%02x", Data[7]);
			sprintf(&f_clean_record_temp[4], "%02x", Data[8]);
			sprintf(&f_clean_record_temp[6], "%02x", Data[9]);
			sprintf(&f_clean_record_temp[8], "%02x", Data[10]);
			sprintf(&f_clean_record_temp[10], "%02x", Data[11]);
			sprintf(&f_clean_record_temp[12], "%02x", Data[12]);
			sprintf(&f_clean_record_temp[14], "%02x", Data[13]);

			if(memcmp(f_clean_record_temp, f_clean_record, 16) != 0)
			{
				memcpy(f_clean_record, f_clean_record_temp, 16);
				prop_send_by_name("f_clean_record", PP_f_clean_record);
			}

			AckSendData[0] = CMD;
			AckSendData[1] = 0x00;
			UartSendFormData(AckSendData, 2);
			break;

		case CMDUpLoadMapInfo:
			if((Length - 8) > 512){
				log_put(LOG_ERR_RF "Map Data too length.Length = %d\n", Length - 8);
				break;
			}
			ilife_ayla_base64_encode(&Data[6], Length - 8, f_realtime_mapinfo, &MapDataLen_encode);
			#if 0
			printf("MapDataLen = %d, MapDataLen_encode = %d.\n", Length - 8, MapDataLen_encode);
			printf("will Send to ADS:");
			for(i = 0; i < MapDataLen_encode; i++){
				printf("%c", f_realtime_mapinfo[i]);
			}
			printf("\n");
			#endif
			
			prop_send_by_name("f_realtime_mapinfo", PP_f_realtime_mapinfo);
			
			AckSendData[0] = CMD;
			AckSendData[1] = 0x00;
			UartSendFormData(AckSendData, 2);
			break;

		case CMDUpLoadSumTime:
			if(f_work_time !=( (Data[6] << 8) | Data[7])){
				f_work_time = ((Data[6] << 8) | Data[7]);
				prop_send_by_name("f_work_time", PP_f_work_time);
			}

			if(f_water_box_time != ((Data[8] << 8) | Data[9])){
				f_water_box_time = ((Data[8] << 8) | Data[9]);
				prop_send_by_name("f_water_box_time", PP_f_water_box_time);
			}

			if(f_dustbin_time != ((Data[10] << 8) | Data[11])){
				f_dustbin_time = ((Data[10] << 8) | Data[11]);
				prop_send_by_name("f_dustbin_time", PP_f_dustbin_time);
			}

			if(f_mul_box_time != ((Data[12] << 8) | Data[13])){
				f_mul_box_time =( (Data[12] << 8) | Data[13]);
				prop_send_by_name("f_mul_box_time", PP_f_mul_box_time);
			}
			AckSendData[0] = CMD;
			AckSendData[1] = 0x00;
			UartSendFormData(AckSendData, 2);
			break;

		case CMDUpLoadFactoryReset:
			//if(t_factory_reset != Data[6]){
			//t_factory_reset = Data[6];
			//prop_send_by_name("t_factory_reset", PP_t_factory_reset);
			//}
			AckSendData[0] = CMD;
			AckSendData[1] = 0x00;
			UartSendFormData(AckSendData, 2);
			break;

		case CMDUpLoadCleanMapInfo:	/* 暂时没有相对应的属性 */

			break;

		case CMDUpLoadLifeTime:
			if(f_edge_brush_lifetime != Data[6]){
				f_edge_brush_lifetime = Data[6];
				prop_send_by_name("f_edge_brush_lifetime", PP_f_edge_brush_lifetime);
			}

			if(f_roll_brush_lifetime != Data[7]){
				f_roll_brush_lifetime = Data[7];
				prop_send_by_name("f_roll_brush_lifetime", PP_f_roll_brush_lifetime);
			}

			if(f_filter_lifetime != Data[8]){
				f_filter_lifetime = Data[8];
				prop_send_by_name("f_filter_lifetime", PP_f_filter_lifetime);
			}
			
			if(f_duster_lifetime != Data[9]){
				f_duster_lifetime = Data[9];
				prop_send_by_name("f_duster_lifetime", PP_f_duster_lifetime);
			}

			if(f_battery_lifetime != Data[10]){
				f_battery_lifetime = Data[10];
				prop_send_by_name("f_battery_lifetime", PP_f_battery_lifetime);
			}

			AckSendData[0] = CMD;
			AckSendData[1] = 0x00;
			UartSendFormData(AckSendData, 2);
			break;

		case CMDUpLoadAppointmentInfo:
			CMDUpLoadAppointmentInfoChange = 0;
			
			for(i = 0; i < 5; i++){
				sprintf(&t_timer_temp[i*2], "%02x", Data[6 + i]);
				if((t_timer_temp[i*2] != t_timer_0[i*2]) || (t_timer_temp[i*2 + 1] != t_timer_0[i*2 + 1])){
					sprintf(&t_timer_0[i*2], "%02x", Data[6 + i]);
					CMDUpLoadAppointmentInfoChange = 1;
				}
			}
			if(CMDUpLoadAppointmentInfoChange != 0){
				prop_send_by_name("t_timer_0", PP_t_timer_0);
				CMDUpLoadAppointmentInfoChange = 0;
			}
			
			for(i = 0; i < 5; i++){
				sprintf(&t_timer_temp[i*2], "%02x", Data[11 + i]);
				if((t_timer_temp[i*2] != t_timer_1[i*2]) || (t_timer_temp[i*2 + 1] != t_timer_1[i*2 + 1])){
					sprintf(&t_timer_1[i*2], "%02x", Data[11 + i]);
					CMDUpLoadAppointmentInfoChange = 1;
				}
			}
			if(CMDUpLoadAppointmentInfoChange != 0){
				prop_send_by_name("t_timer_1", PP_t_timer_1);
				CMDUpLoadAppointmentInfoChange = 0;
			}
			
			for(i = 0; i < 5; i++){
				sprintf(&t_timer_temp[i*2], "%02x", Data[16 + i]);
				if((t_timer_temp[i*2] != t_timer_2[i*2]) || (t_timer_temp[i*2 + 1] != t_timer_2[i*2 + 1])){
					sprintf(&t_timer_2[i*2], "%02x", Data[16 + i]);
					CMDUpLoadAppointmentInfoChange = 1;
				}
			}
			if(CMDUpLoadAppointmentInfoChange != 0){
				prop_send_by_name("t_timer_2", PP_t_timer_2);
				CMDUpLoadAppointmentInfoChange = 0;
			}

			for(i = 0; i < 5; i++){
				sprintf(&t_timer_temp[i*2], "%02x", Data[21 + i]);
				if((t_timer_temp[i*2] != t_timer_3[i*2]) || (t_timer_temp[i*2 + 1] != t_timer_3[i*2 + 1])){
					sprintf(&t_timer_3[i*2], "%02x", Data[21 + i]);
					CMDUpLoadAppointmentInfoChange = 1;
				}
			}
			if(CMDUpLoadAppointmentInfoChange != 0){
				prop_send_by_name("t_timer_3", PP_t_timer_3);
				CMDUpLoadAppointmentInfoChange = 0;
			}
			
			for(i = 0; i < 5; i++){
				sprintf(&t_timer_temp[i*2], "%02x", Data[26 + i]);
				if((t_timer_temp[i*2] != t_timer_4[i*2]) || (t_timer_temp[i*2 + 1] != t_timer_4[i*2 + 1])){
					sprintf(&t_timer_4[i*2], "%02x", Data[26 + i]);
					CMDUpLoadAppointmentInfoChange = 1;
				}
			}
			if(CMDUpLoadAppointmentInfoChange != 0){
				prop_send_by_name("t_timer_4", PP_t_timer_4);
				CMDUpLoadAppointmentInfoChange = 0;
			}
			
			for(i = 0; i < 5; i++){
				sprintf(&t_timer_temp[i*2], "%02x", Data[31 + i]);
				if((t_timer_temp[i*2] != t_timer_5[i*2]) || (t_timer_temp[i*2 + 1] != t_timer_5[i*2 + 1])){
					sprintf(&t_timer_5[i*2], "%02x", Data[31 + i]);
					CMDUpLoadAppointmentInfoChange = 1;
				}
			}
			if(CMDUpLoadAppointmentInfoChange != 0){
				prop_send_by_name("t_timer_5", PP_t_timer_5);
				CMDUpLoadAppointmentInfoChange = 0;
			}
			
			for(i = 0; i < 5; i++){
				sprintf(&t_timer_temp[i*2], "%02x", Data[36 + i]);
				if((t_timer_temp[i*2] != t_timer_6[i*2]) || (t_timer_temp[i*2 + 1] != t_timer_6[i*2 + 1])){
					sprintf(&t_timer_6[i*2], "%02x", Data[36 + i]);
					CMDUpLoadAppointmentInfoChange = 1;
				}
			}
			if(CMDUpLoadAppointmentInfoChange != 0){
				prop_send_by_name("t_timer_6", PP_t_timer_6);
				CMDUpLoadAppointmentInfoChange = 0;
			}
			
			for(i = 0; i < 5; i++){
				sprintf(&t_timer_temp[i*2], "%02x", Data[41 + i]);
				if((t_timer_temp[i*2] != t_timer_7[i*2]) || (t_timer_temp[i*2 + 1] != t_timer_7[i*2 + 1])){
					sprintf(&t_timer_7[i*2], "%02x", Data[41 + i]);
					CMDUpLoadAppointmentInfoChange = 1;
				}
			}
			if(CMDUpLoadAppointmentInfoChange != 0){
				prop_send_by_name("t_timer_7", PP_t_timer_7);
				CMDUpLoadAppointmentInfoChange = 0;
			}
			
			for(i = 0; i < 5; i++){
				sprintf(&t_timer_temp[i*2], "%02x", Data[46 + i]);
				if((t_timer_temp[i*2] != t_timer_8[i*2]) || (t_timer_temp[i*2 + 1] != t_timer_8[i*2 + 1])){
					sprintf(&t_timer_8[i*2], "%02x", Data[46 + i]);
					CMDUpLoadAppointmentInfoChange = 1;
				}
			}
			if(CMDUpLoadAppointmentInfoChange != 0){
				prop_send_by_name("t_timer_8", PP_t_timer_8);
				CMDUpLoadAppointmentInfoChange = 0;
			}
			
			for(i = 0; i < 5; i++){
				sprintf(&t_timer_temp[i*2], "%02x", Data[51 + i]);
				if((t_timer_temp[i*2] != t_timer_9[i*2]) || (t_timer_temp[i*2 + 1] != t_timer_9[i*2 + 1])){
					sprintf(&t_timer_9[i*2], "%02x", Data[51 + i]);
					CMDUpLoadAppointmentInfoChange = 1;
				}
			}
			if(CMDUpLoadAppointmentInfoChange != 0){
				prop_send_by_name("t_timer_9", PP_t_timer_9);
				CMDUpLoadAppointmentInfoChange = 0;
			}

			AckSendData[0] = CMD;
			AckSendData[1] = 0x00;
			UartSendFormData(AckSendData, 2);
			break;

		case CMDUpLoadReset:
			if(t_reset_edge_brush != Data[6]){
				t_reset_edge_brush = Data[6];
				prop_send_by_name("t_reset_edge_brush", PP_t_reset_edge_brush);
			}

			if(t_reset_roll_brush != Data[7]){
				t_reset_roll_brush = Data[7];
				prop_send_by_name("t_reset_roll_brush", PP_t_reset_roll_brush);
			}

			if(t_reset_filter != Data[8]){
				t_reset_filter = Data[8];
				prop_send_by_name("t_reset_filter", PP_t_reset_filter);
			}

			if(t_reset_duster != Data[9]){
				t_reset_duster = Data[9];
				prop_send_by_name("t_reset_duster", PP_t_reset_duster);
			}

			if(t_reset_power != Data[10]){
				t_reset_power = Data[10];
				prop_send_by_name("t_reset_power", PP_t_reset_power);
			}

			AckSendData[0] = CMD;
			AckSendData[1] = 0x00;
			UartSendFormData(AckSendData, 2);
			break;

		case CMDUpLoadSearch:
			if(t_search != Data[6]){
				t_search = Data[6];
				prop_send_by_name("t_search", PP_t_search);
			}
			AckSendData[0] = CMD;
			AckSendData[1] = 0x00;
			UartSendFormData(AckSendData, 2);
			break;

		case CMDUpLoadControl:
			if(t_control != Data[6]){
				t_control = Data[6];
				prop_send_by_name("t_control", PP_t_control);
			}
			AckSendData[0] = CMD;
			AckSendData[1] = 0x00;
			UartSendFormData(AckSendData, 2);
			break;

		case CMDUpLoadFWVersion:
			sprintf(MCUFWversion, " fw-%08d", (Data[6]<<24) | (Data[7]<<16) | (Data[8]<<8) | (Data[9]<<0));
			memset(version, 0x00, 64);
			memcpy(version, version_temp, strlen(version_temp));
			strncat(version, MCUFWversion, 12);

			prop_send_by_name("version", PP_version);
			
			AckSendData[0] = CMD;
			AckSendData[1] = 0x00;
			UartSendFormData(AckSendData, 2);
			break;

		case CMDUpLoadRealTimeStart:
			f_upload_realmap_starttime[0] = Data[6];	//年
			f_upload_realmap_starttime[2] = Data[7];	//年
			f_upload_realmap_starttime[4] = Data[8];	//月
			f_upload_realmap_starttime[6] = Data[9];	//日
			f_upload_realmap_starttime[8] = Data[10];	//星期
			f_upload_realmap_starttime[10] = Data[11];	//时
			f_upload_realmap_starttime[12] = Data[12];	//分
			f_upload_realmap_starttime[14] = Data[13];	//秒

			#if 0
			printf("Recv f_upload_realmap_starttime:");
			for(i = 0; i < 16; i++){
				printf("%02x ", f_upload_realmap_starttime[i]);
			}
			printf("\n");
			#endif
			//年月日时分秒
			clock_ints_to_time(&LocalToUTCtime, f_upload_realmap_starttime[0] << 8 | f_upload_realmap_starttime[2], f_upload_realmap_starttime[4], 
				f_upload_realmap_starttime[6], f_upload_realmap_starttime[10], f_upload_realmap_starttime[12], f_upload_realmap_starttime[14]);

			//printf("LocalToUTCtime = %u, %x, %x, %x, %x, %x, %x, %x\n", LocalToUTCtime, f_upload_realmap_starttime[0], f_upload_realmap_starttime[2], f_upload_realmap_starttime[4], f_upload_realmap_starttime[6],f_upload_realmap_starttime[10], f_upload_realmap_starttime[12], f_upload_realmap_starttime[14]);
			LocalToUTCtime = clock_local_to_utc(LocalToUTCtime, 0);
			//printf("LocalToUTCtime = %u\n", LocalToUTCtime);
			clock_fill_details(&clk, LocalToUTCtime);
			//printf("%x, %x, %x, %x, %x, %x, %x\n", clk.year, clk.month, clk.days, clk.day_of_week, clk.hour, clk.min, clk.sec);
			sprintf(&f_upload_realmap_starttime[0], "%02x", ((clk.year >> 8) & 0xFF));	//年
			sprintf(&f_upload_realmap_starttime[2], "%02x", (clk.year & 0xFF));			//年
			sprintf(&f_upload_realmap_starttime[4], "%02x", clk.month);
			sprintf(&f_upload_realmap_starttime[6], "%02x", clk.days);
			sprintf(&f_upload_realmap_starttime[8], "%02x", clk.day_of_week);
			sprintf(&f_upload_realmap_starttime[10], "%02x", clk.hour);
			sprintf(&f_upload_realmap_starttime[12], "%02x", clk.min);
			sprintf(&f_upload_realmap_starttime[14], "%02x", clk.sec);
			prop_send_by_name("f_upload_realmap_starttime", PP_f_upload_realmap_starttime);

			AckSendData[0] = CMD;
			AckSendData[1] = 0x00;
			UartSendFormData(AckSendData, 2);
			break;

		case CMDUpLoadRealInfoSwitch:
			if(t_realtime_info != Data[6]){
				t_realtime_info = Data[6];
				prop_send_by_name("t_realtime_info", PP_t_realtime_info);
			}

			AckSendData[0] = CMD;
			AckSendData[1] = 0x00;
			UartSendFormData(AckSendData, 2);
			break;

		//下发指令
		case CMDDownWorkMode:
			SendRespondCMD = CMD;
			break;
			
		case CMDDownRoomMode:
			SendRespondCMD = CMD;
			break;
			
		case CMDDownCleanStrength:
			SendRespondCMD = CMD;
			break;
			
		case CMDDownControl:
			SendRespondCMD = CMD;
			break;
			
		case CMDDownTimer:
			SendRespondCMD = CMD;
			break;
			
		case CMDDownReset:
			SendRespondCMD = CMD;
			break;
			
		case CMDDownCalTime:
			SendRespondCMD = CMD;
			break;
			
		case CMDDownupRealtimeInfo:
			SendRespondCMD = CMD;
			break;
			
		case CMDDownDisturb:
			SendRespondCMD = CMD;
			break;
			
		case CMDDownFactoryReset:
			SendRespondCMD = CMD;
			break;
			
		case CMDDownSearch:
			SendRespondCMD = CMD;
			break;

		//设备查询指令
		case CMDRequeryDeviceStatus:
			t_work_mode = Data[6];
			t_room_mode = Data[7];
			f_clean_mode = Data[8];
			t_d_strength = Data[9];
			t_p_strength = Data[10];
			f_battery = Data[11];
			t_sound = Data[12];
			t_light = Data[13];
			ff_error = Data[14];
			
			prop_send_by_name("t_work_mode", PP_t_work_mode);
			prop_send_by_name("t_room_mode", PP_t_room_mode);
			prop_send_by_name("f_clean_mode", PP_f_clean_mode);
			prop_send_by_name("t_d_strength", PP_t_d_strength);
			prop_send_by_name("t_p_strength", PP_t_p_strength);
			prop_send_by_name("f_battery", PP_f_battery);
			prop_send_by_name("t_sound", PP_t_sound);
			prop_send_by_name("t_light", PP_t_light);
			prop_send_by_name("f_error", PP_f_error);
	
			SendRespondCMD = CMD;
			break;

		case CMDRequeryTimerInfo:
			for(i = 0; i < 5; i++){
				sprintf(&t_timer_0[i*2], "%02x", Data[6 + i]);
			}
			prop_send_by_name("t_timer_0", PP_t_timer_0);
			
			for(i = 0; i < 5; i++){
				sprintf(&t_timer_1[i*2], "%02x", Data[11 + i]);
			}
			prop_send_by_name("t_timer_1", PP_t_timer_1);
			
			for(i = 0; i < 5; i++){
				sprintf(&t_timer_2[i*2], "%02x", Data[16 + i]);
			}
			prop_send_by_name("t_timer_2", PP_t_timer_2);
			
			for(i = 0; i < 5; i++){
				sprintf(&t_timer_3[i*2], "%02x", Data[21 + i]);
			}
			prop_send_by_name("t_timer_3", PP_t_timer_3);
			
			for(i = 0; i < 5; i++){
				sprintf(&t_timer_4[i*2], "%02x", Data[26 + i]);
			}
			prop_send_by_name("t_timer_4", PP_t_timer_4);
			
			for(i = 0; i < 5; i++){
				sprintf(&t_timer_5[i*2], "%02x", Data[31 + i]);
			}
			prop_send_by_name("t_timer_5", PP_t_timer_5);
			
			for(i = 0; i < 5; i++){
				sprintf(&t_timer_6[i*2], "%02x", Data[36 + i]);
			}
			prop_send_by_name("t_timer_6", PP_t_timer_6);
			
			for(i = 0; i < 5; i++){
				sprintf(&t_timer_7[i*2], "%02x", Data[41 + i]);
			}
			prop_send_by_name("t_timer_7", PP_t_timer_7);
			
			for(i = 0; i < 5; i++){
				sprintf(&t_timer_8[i*2], "%02x", Data[46 + i]);
			}
			prop_send_by_name("t_timer_8", PP_t_timer_8);
			
			for(i = 0; i < 5; i++){
				sprintf(&t_timer_9[i*2], "%02x", Data[51 + i]);
			}
			prop_send_by_name("t_timer_9", PP_t_timer_9);
			
			SendRespondCMD = CMD;
			break;

		case CMDRequeryLifeTime:
			f_edge_brush_lifetime = Data[6];
			f_roll_brush_lifetime = Data[7];
			f_filter_lifetime = Data[8];
			f_duster_lifetime = Data[9];
			f_battery_lifetime = Data[10];

			prop_send_by_name("f_edge_brush_lifetime", PP_f_edge_brush_lifetime);
			prop_send_by_name("f_roll_brush_lifetime", PP_f_roll_brush_lifetime);
			prop_send_by_name("f_filter_lifetime", PP_f_filter_lifetime);
			prop_send_by_name("f_duster_lifetime", PP_f_duster_lifetime);
			prop_send_by_name("f_battery_lifetime", PP_f_battery_lifetime);
	
			SendRespondCMD = CMD;
			break;

		case CMDRequeryFWVersion:
			sprintf(MCUFWversion, " fw-%08d", (Data[6]<<24) | (Data[7]<<16) | (Data[8]<<8) | (Data[9]<<0));
			memset(version, 0x00, 64);
			memcpy(version, version_temp, strlen(version_temp));
			strncat(version, MCUFWversion, 12);

			prop_send_by_name("version", PP_version);
			
			SendRespondCMD = CMD;
			break;

		//系统指令
		case CMDSysNetWorking:
			SendRespondCMD = CMD;
			break;
			
		case CMDSysNetBroken:
			SendRespondCMD = CMD;
			break;
			
		case CMDSysCloudWorking:
			SendRespondCMD = CMD;
			break;
			
		case CMDSysCloudBroken:
			SendRespondCMD = CMD;
			break;

		case CMDSysConfNetWork:
			AckSendData[0] = CMD;
			AckSendData[1] = 0x00;
			UartSendFormData(AckSendData, 2);
			
			ForceWifiErase();	
			break;
			
		case CMDSysQueryNTP:
			if((Data[6] == 0xF0) && (Data[7] == 0x0F) ){
				NTP_utc = clock_utc();	//获取utc时间
				NTP_local = clock_local(&NTP_utc);//获取本地时间
				clock_fill_details(&clk, NTP_local);
				SendSysNTP(clk, NTP_local);
				//printf("%4.4lu-%2.2u-%2.2uT%2.2u:%2.2u:%2.2u  %2.2u, NTP=%lu, NTP_LOCAL=%lu\n\n",
				//	    clk.year, clk.month, clk.days, clk.hour, clk.min, clk.sec, clk.day_of_week, NTP_utc, NTP_local);
			}
			break;
			
		case CMDSysGetSigQuality:
			adap_net_get_signal(&WifiSignal);	//获取信号质量
			SendWifiSignal(abs(WifiSignal));
			//printf("Wifi Signal is:%d.	%d\n", WifiSignal, abs(WifiSignal));
			break;
			
		case CMDRequeryMACAddr:
			mac = LwIP_GetMAC(&xnetif[0]);
			
			printf("mac addr:");
			for(i = 0; i < 6; i++)
			{
				printf("%02x ", mac[i]);
			}
			printf("\n");
			
			AckSendData[0] = CMD;
			AckSendData[1] = mac[0];
			AckSendData[2] = mac[1];
			AckSendData[3] = mac[2];
			AckSendData[4] = mac[3];
			AckSendData[5] = mac[4];
			AckSendData[6] = mac[5];
			UartSendFormData(AckSendData, 7);
			break;

		case CMDRequerySWVersion:
			AckSendData[0] = CMD;
			/* get host version */
			for(i = 0; i < strlen(demo_host_version); i++){
				AckSendData[1 + i] = demo_host_version[i];
			}
			VersionLen = i + 1;

			/* get mcu version */
			for(i = 0; i < strlen(MCUFWversion); i++){
				AckSendData[VersionLen + i] = MCUFWversion[i];
			}

			VersionLen = VersionLen + i;
			#if 0
			AckSendData[1] = demo_host_version[0];
			AckSendData[2] = demo_host_version[1];
			AckSendData[3] = demo_host_version[2];
			AckSendData[4] = demo_host_version[3];
			AckSendData[5] = demo_host_version[4];
			AckSendData[6] = demo_host_version[5];
			AckSendData[7] = demo_host_version[6];
			AckSendData[8] = demo_host_version[7];
			#endif
			
			UartSendFormData(AckSendData,  VersionLen);
			log_put(LOG_INFO_RF "host SW version:%s, MCU version:%s", demo_host_version, MCUFWversion);
			break;

		default:
			log_put(LOG_ERR_RF "Recv unknow CMD.\n");
			break;
	}
}
/***************************************************************************************/
/* 增加缓存区的读写下标 */
unsigned char AddRing (unsigned char i)
{
       return (i+1) == SENDBUFFERMAXLEN ? 0 : i+1;
}

void WriteRingBuffer(unsigned char *Data, unsigned short Len)
{
	if(DataNum < SENDBUFFERMAXLEN)
	{
		memcpy(RingSendBuffer[W_CurSor].Data, Data, Len);
		RingSendBuffer[W_CurSor].Length = Len;

		W_CurSor = AddRing(W_CurSor);
		DataNum++;
		
	}
	else
	{
		log_put(LOG_ERR_RF "Ring Buffer is full.\n");
	}
}

/* 读数据到环形缓冲区 */
void ReadRingBuffer(void)
{
	unsigned char ReadPos;
	int cnt = 0;
	
	if(DataNum > 0)
	{
		ReadPos = R_CurSor;
		/* RingSendBuffer[ReadPos].Data[0]是CMD字段 */
		SendRespondCMD = 0x00;
		while(SendRespondCMD != RingSendBuffer[ReadPos].Data[0]){
			if((cnt%SENDGAPTIME) == 0){
				UartSendFormData(RingSendBuffer[ReadPos].Data, RingSendBuffer[ReadPos].Length);
			}

			if(cnt > SENDCNT){
				log_put(LOG_ERR_RF "Data is Send, But MCU not Respond.CMD = %02x\n", RingSendBuffer[ReadPos].Data[0]);
				break;
			}
			cnt++;
			vTaskDelay(SENDDELAYTIME);
		}
		/* 应该在处理完数据之后再移动坐标 */
		R_CurSor = AddRing(R_CurSor);
		DataNum--;
	}
	else{
		log_put(LOG_ERR_RF "Ring Buffer is empty.\b");
	}
}

/**************************************************************************************/

/* 增加缓存区的读写下标 */
unsigned char AddRingRecv(unsigned char i)
{
       return (i+1) == RECVBUFFERMAXLEN ? 0 : i+1;
}

/* 写数据到环形缓冲区 */
void WriteRingBufferRecv(unsigned char *Data, unsigned short Len)
{
	if(DataNumRecv < RECVBUFFERMAXLEN){
		RingRecvBuffer[W_CurSorRecv].CMD = Data[5];
		memcpy(RingRecvBuffer[W_CurSorRecv].Data, &Data[0], Len);
		RingRecvBuffer[W_CurSorRecv].Length = Len;

		W_CurSorRecv = AddRingRecv(W_CurSorRecv);
		DataNumRecv++;
		
	}
	else{
		log_put(LOG_ERR_RF "Ring Recv Buffer is full.\n");
	}
}

/* 读数据到环形缓冲区 */
void ReadRingBufferRecv(void)
{
	unsigned char ReadPos;
	
	if(DataNumRecv > 0){
		ReadPos = R_CurSorRecv;
		ProtocalUartData(RingRecvBuffer[ReadPos].CMD, RingRecvBuffer[ReadPos].Data, RingRecvBuffer[ReadPos].Length);
		/* 应该在处理完数据之后再移动坐标 */
		R_CurSorRecv = AddRingRecv(R_CurSorRecv);
		DataNumRecv--;
	}
	else{
		log_put(LOG_ERR_RF "Ring Recv Buffer is empty.\b");
	}
}

/***********************************串口数据的发送和接收处理线程*****************************/
static void SendBufferHandler( void *pvParameters )
{
	while(1)
	{
		vTaskDelay(20);
		watchdog_refresh();
		while(DataNum != 0){
			ReadRingBuffer();
		}
	}
}

static void RecvBufferHandler( void *pvParameters )
{
	while(1)
	{
		vTaskDelay(20);
		watchdog_refresh();
		while(DataNumRecv != 0){
			ReadRingBufferRecv();
		}
	}
}

/************************************ 串口相关的初始化 *************************************/
void ILIFEUartIRQ(uint32_t id, SerialIrq event)
{
	serial_t    *sobj = (void*)id;
	
	if(event == RxIrq)
	{
		RecvCharTemp = serial_getc(sobj);
		switch(UartStatus)
		{
			case UartNOP:
			{
				if(UartRxOkFlag){
					break;
				}else{
					UartStatus = UartSOP;
				}
			}

			case UartSOP:
			{
				if(RecvCharTemp == F_HEAD){
					RecvBuffer[UartRecvLen++] = RecvCharTemp;
					UartStatus = UartLEN_H;
					UartIrqRecvTimeOut = 1;
				}
				break;
			}

			case UartLEN_H:
			{
				RecvBuffer[UartRecvLen++] = RecvCharTemp;
				CalCRC += RecvCharTemp;
				UartDataLen = RecvCharTemp << 8;
				UartStatus = UartLEN_L;
				break;
			}

			case UartLEN_L:
			{
				RecvBuffer[UartRecvLen++] = RecvCharTemp;
				CalCRC += RecvCharTemp;
				UartDataLen |= RecvCharTemp ;
				UartStatus = UartRESV_H;
				break;
			}

			case UartRESV_H:
			{
				RecvBuffer[UartRecvLen++] = RecvCharTemp;
				CalCRC += RecvCharTemp;
				UartStatus = UartRESV_L;
				break;
			}

			case UartRESV_L:
			{
				RecvBuffer[UartRecvLen++] = RecvCharTemp;
				CalCRC += RecvCharTemp;
				UartStatus = UartCMD;
				break;
			}

			case UartCMD:
			{
				RecvBuffer[UartRecvLen++] = RecvCharTemp;
				CalCRC += RecvCharTemp;
				UartStatus = UartDATA;
				break;
			}

			case UartDATA:
			{
				if(UartDataLen > 8)
				{
					RecvBuffer[UartRecvLen++] = RecvCharTemp;
					CalCRC += RecvCharTemp;
					UartDataLen--;
					break;
				}
				else{
					UartStatus = UartCRC;
				}
			}

			case UartCRC:
			{
				RecvBuffer[UartRecvLen++] = RecvCharTemp;
				RecvCRC = RecvCharTemp;
				UartStatus = UartEND;
				break;
			}

			case UartEND:
			{
				RecvBuffer[UartRecvLen++] = RecvCharTemp;
				
				if((RecvCRC == CalCRC) && (RecvCharTemp == F_END))
				{
					UartRxOkFlag = 1;
					/* 存入循环buffer */
					WriteRingBufferRecv(RecvBuffer, UartRecvLen);

					/* init */
					memset(RecvBuffer, 0x00, RecvMAXLen);
					UartRxOkFlag = 0;
					UartRecvLen = 0;
					UartDataLen = 0;
					CalCRC = 0;
					RecvCRC = 0;
					UartStatus = UartNOP;
					RecvCharTemp = 0;
					UartIrqRecvTimeOut = 0;
				}else
				{
					log_put(LOG_ERR_RF "Recv CRC Error or Frame END Error.Recv CRC=%02x, expect CRC=%02x, Frame END = %02x\n", RecvCRC, CalCRC, RecvCharTemp);

					/* init */
					UartIrqRecvTimeOut=0;
					UartRecvLen = 0;
					UartDataLen = 0;
					CalCRC = 0;
					RecvCRC = 0;
					UartStatus = UartNOP;
					UartRxOkFlag = 0;
					RecvCharTemp = 0;
					memset(RecvBuffer, 0x00, RecvMAXLen);
				}
			}
		}
	}
}

/* 在定时器里面调用，接收超时 */
void UartErrorRecvTimeout(void)
{	
	if(UartIrqRecvTimeOut != 0)	
	{		
		UartIrqRecvTimeOut++;	
		if(UartIrqRecvTimeOut > 10)	/* 1000ms没有接收完成则丢弃该帧数据 */
		{
			/* init */
			UartIrqRecvTimeOut=0;
			UartRecvLen = 0;
			UartDataLen = 0;
			CalCRC = 0;
			RecvCRC = 0;
			UartStatus = UartNOP;
			UartRxOkFlag = 0;
			RecvCharTemp = 0;
			memset(RecvBuffer, 0x00, RecvMAXLen);
		}
	}
}

/*************************************低功耗函数*******************************************/
void releasewakelock(void)
{
	pmu_release_wakelock(BIT(PMU_DEV_USER_BASE));
}

void acquirewakelock(void)
{
	pmu_acquire_wakelock(BIT(PMU_DEV_USER_BASE));
	AutoEnterLowpower = 1;
}

void sysreleasewakelock(void)
{
	pmu_release_wakelock(BIT(PMU_OS));
}

/* 100ms定时器中断 */
void timer1_timeout_handler(unsigned int TimeOut)
{
	UartErrorRecvTimeout();

	if(AutoEnterLowpower > 0)
	{
		AutoEnterLowpower++;
		if(AutoEnterLowpower > 50)
		{	/* 唤醒5秒还没有动作，自动进入低功耗 */
			AutoEnterLowpower = 0;
			releasewakelock();
		}
	}
}

/* gpio中断处理函数 */
void GpioUartRXIrqCallback (uint32_t id, gpio_irq_event event)
{
	acquirewakelock();
}

/* 看门狗中断处理函数 */
void ilife_watchdog_irq_handler(uint32_t id)
{
	log_put(LOG_ERR_RF "!!!!!!watchdog barks!!!!!!\r\n");
	ada_conf_reset(0);
}


/********************************* 相关初始化函数 ********************************/
void ILIFESweeperInit(void)
{
	gpio_irq_t GpioRXWakeup;
	
	//串口初始化
	serial_init(&sobj,UART_TX,UART_RX);
	serial_baud(&sobj,115200);
	serial_format(&sobj, 8, ParityNone, 1);
	
	serial_irq_handler(&sobj, ILIFEUartIRQ, (uint32_t)&sobj);
	serial_irq_set(&sobj, RxIrq, 1);
	serial_irq_set(&sobj, TxIrq, 1);

	//定时器初始化	100ms进入一次定时器中断
	gtimer_init(&SweeperTimer, TIMER0);
	gtimer_start_periodical(&SweeperTimer, 100000, (void*)timer1_timeout_handler, NULL);

	//gpio初始化
	gpio_irq_init(&GpioRXWakeup, PC_1, GpioUartRXIrqCallback, NULL);
	gpio_irq_set(&GpioRXWakeup, IRQ_FALL, 1);
	gpio_irq_enable(&GpioRXWakeup);
	/* 发送线程 */
	xTaskCreate( SendBufferHandler, "SendBufferHandler", 512, NULL, tskIDLE_PRIORITY + 2 + PRIORITIE_OFFSET, NULL );
	/* 接收线程 */
	xTaskCreate( RecvBufferHandler, "RecvBufferHandler", 512, NULL, tskIDLE_PRIORITY + 2 + PRIORITIE_OFFSET, NULL );

	//初始化看门狗
	//watchdog init
	watchdog_init(10000);	//10s
	watchdog_irq_init(ilife_watchdog_irq_handler, 0);
	watchdog_start();
	watchdog_refresh();

	memset(version, 0x00, 64);
	memcpy(version, version_temp, strlen(version_temp));
	printf("SweeperInit OK. version: %s, %s\n", demo_host_version, version);

	/* 使系统进入低功耗状态 */
	sysreleasewakelock();
	releasewakelock();
}


/* 设备查询接口 */
/* 查询设备状态信息 */
void RequeryDeviceStatus(void)
{
	unsigned char Data[2] = {0};

	Data[0] = CMDRequeryDeviceStatus;
	Data[1] = 0x00;
	WriteRingBuffer(Data, 2);
}

/* 查询预约信息 */
void RequeryTimerInfo(void)
{
	unsigned char Data[2] = {0};

	Data[0] = CMDRequeryTimerInfo;
	Data[1] = 0x00;
	WriteRingBuffer(Data, 2);
}

/* 查询耗材情况 */
void RequeryLifeTime(void)
{
	unsigned char Data[2] = {0};

	Data[0] = CMDRequeryLifeTime;
	Data[1] = 0x00;
	WriteRingBuffer(Data, 2);
}

/* 查询MCU固件版本 */
void RequeryFWVersion(void)
{
	unsigned char Data[2] = {0};

	Data[0] = CMDRequeryFWVersion;
	Data[1] = 0x00;
	WriteRingBuffer(Data, 2);
}

/* 系统指令接口 */
/* 联网通知 */
void SendNetWorkStatus(unsigned char NetConnetFlag)
{	
	unsigned char Data[3] = {0};
	
	if(NetConnetFlag == 1){				//联网
		Data[0] = CMDSysNetWorking;
		Data[1] = 0xF0;
		Data[2] = 0x0F;
	}else{								//断网
		Data[0] = CMDSysNetBroken;
		Data[1] = 0xF1;
		Data[2] = 0x1F;
	}
	WriteRingBuffer(Data, 3);
}

/* 联云通知 */
void SendCloudStatus(unsigned char CloudStatus)
{
	unsigned char Data[3] = {0};
	
	if(CloudStatus == 1){				//联云
		Data[0] = CMDSysCloudWorking;
		Data[1] = 0xF0;
		Data[2] = 0x0F;
	}else{						//断云
		Data[0] = CMDSysCloudBroken;
		Data[1] = 0xF1;
		Data[2] = 0x1F;
	}
	WriteRingBuffer(Data, 3);
}

/* 发送时间给扫地机 */
void SentNTPToSweeper(void)
{
	struct clock_info clk;
	unsigned int NTP_utc = 0;	//utc时间
	unsigned int NTP_local = 0;	//本地时间
	
	NTP_utc = clock_utc();	//获取utc时间
	NTP_local = clock_local(&NTP_utc);//获取本地时间
	clock_fill_details(&clk, NTP_local);
	SendSysNTP(clk, NTP_local);
	//printf("%4.4lu-%2.2u-%2.2uT%2.2u:%2.2u:%2.2u  %2.2u, NTP=%lu, NTP_LOCAL=%lu\n\n",
	//	    clk.year, clk.month, clk.days, clk.hour, clk.min, clk.sec, clk.day_of_week, NTP_utc, NTP_local);
}

