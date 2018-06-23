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


/* ����ѭ������buffer */
SECTION(".sdram.data") struct RingSendBuffer_t RingSendBuffer[SENDBUFFERMAXLEN] = {0};
unsigned char R_CurSor = 0;	/* ��λ�� */
unsigned char W_CurSor = 0;	/* дλ�� */
unsigned char DataNum = 0;	/* ���λ������е�Ԫ�������� */
/* �������ѭ��buffer */
SECTION(".sdram.data") struct RingRecvBuffer_t RingRecvBuffer[RECVBUFFERMAXLEN] = {0};
unsigned char R_CurSorRecv = 0;	/* ��λ�� */
unsigned char W_CurSorRecv = 0;	/* дλ�� */
unsigned char DataNumRecv = 0;	/* ���λ������е�Ԫ�������� */

serial_t sobj;
gtimer_t SweeperTimer;
#define UART_TX    PA_7
#define UART_RX    PA_6

unsigned char RecvCharTemp = 0;
unsigned char UartStatus = UartNOP;
unsigned char UartRxOkFlag = 0;
SECTION(".sdram.data") static unsigned char RecvBuffer[RecvMAXLen] = {0};
unsigned short UartRecvLen = 0;
unsigned short UartDataLen = 0;		/* ���ݰ����������ݰ��ĳ��ȣ�������ͷ�������ȡ� �����ȡ� ����λ�� ����λ�������롢���ݡ�У��͡���β�� */
unsigned char CalCRC = 0;	/* ���������CRC���� */
unsigned char RecvCRC = 0;	/* ���յ���CRC���� */
unsigned char UartIrqRecvTimeOut = 0;	/* �����жϽ��ճ�ʱ��־����ֹ���ʹ������ݵ�ʱ��Ӱ����һ֡�Ľ��� */

/* ���ڷ���ʱ��Ƭ���Ļظ����� */
unsigned char SendRespondCMD = 0x00;

/* ����͹��ı�־λ */
unsigned char AutoEnterLowpower = 0;

/* base64���� */
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
	printf("*outlen = %d, len2 = %d\n", *outlen, len2);
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
/* SendFormData����CMD��Data�ֶ�, len�ĳ�����SendFormData�ĳ��� */
void UartSendFormData(const unsigned char *SendFormData, unsigned short Len)
{
	unsigned char SendDataTem[SendMAXLen + 7] = {0};
	unsigned short SendDataLen = 0;
	unsigned char CRCTem = 0;
	unsigned short i;
	
	SendDataTem[SendDataLen++] = F_HEAD;					//��ͷ
	SendDataTem[SendDataLen++] = ((Len + 7)>>8) & 0xFF;		//������8λ
	CRCTem += SendDataTem[SendDataLen - 1];
	SendDataTem[SendDataLen++] = ((Len + 7)>>0) & 0xFF;		//�����Ͱ�λ
	CRCTem += SendDataTem[SendDataLen - 1];
	
	SendDataTem[SendDataLen++] = 0x00;			//����λ
	CRCTem += SendDataTem[SendDataLen - 1];
	SendDataTem[SendDataLen++] = 0x00;			//����λ
	CRCTem += SendDataTem[SendDataLen - 1];
	
	SendDataTem[SendDataLen++] = SendFormData[0];					//������
	CRCTem += SendDataTem[SendDataLen - 1];

	for(i = 0; i < Len - 1; i++){
		SendDataTem[SendDataLen++] = SendFormData[i + 1];		//����
		CRCTem += SendDataTem[SendDataLen - 1];
	}

	SendDataTem[SendDataLen++] = CRCTem;					//У���
	SendDataTem[SendDataLen++] = F_END;						//��β

	//��ʼ��������
	PRINTFSendBuffer(SendDataTem, SendDataLen);
	
	for(i = 0; i < SendDataLen; i++)
	{
		serial_putc(&sobj, SendDataTem[i]);
	}
}

/* ����ģ��]wifi��Ϣ */
void ForceWifiErase(void)
{
	int i = 0;
	
	vTaskDelay(2000);	//2s
	for(i = 0; i < 11; i++)
	{
		adw_wifi_profile_erase(i);
	}
	
	conf_save_config();
	printf("Wifi erase ok.\n");
	ada_conf_reset(0);
}

void SendSysNTP(struct clock_info clk, unsigned int NTP_utc)
{
	unsigned char Data[13];

	Data[0] = CMDSysQueryNTP;

	//��
	Data[1] = (clk.year >> 8) & 0xFF;
	Data[2] = clk.year & 0xFF;
	//��
	Data[3] = clk.month;
	//��
	Data[4] = clk.days;
	//����
	Data[5] = clk.day_of_week;
	//ʱ
	Data[6] = clk.hour;
	//��
	Data[7] = clk.min;
	//��
	Data[8] = clk.sec;
	//NTP����
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


/* ���ڽ������ݴ��������������ݰ���֡ͷ֡β��һ��֡���� */
void ProtocalUartData(unsigned char CMD, unsigned char *Data, unsigned short Length)
{
	int i;
	unsigned int MapDataLen_encode = 686;
	unsigned char AckSendData[10] = {0};	/* ���ص�Ƭ����Data */
	static unsigned char CMDUpLoadAppointmentInfoChange = 0;
	
	struct clock_info clk;
	unsigned int LocalToUTCtime;
	unsigned int NTP_utc = 0;	//utcʱ��
	unsigned int NTP_local = 0;	//����ʱ��

	int WifiSignal;	//WIFI���ź�����

	unsigned char *mac;
	
	printf("Recv Data:");
	for(i = 0; i < Length; i++)
	{
		printf("%02x ", Data[i]);
	}
	printf("\n");

	switch(CMD)
	{
		//�ϴ�ָ��
		case CMDUpLoadStatus:
			if(t_work_mode != Data[6]){
				t_work_mode = Data[6];
				prop_send_by_name("t_work_mode");
			}

			if(t_room_mode != Data[7]){
				t_room_mode = Data[7];
				prop_send_by_name("t_room_mode");
			}

			if(f_clean_mode != Data[8]){
				f_clean_mode = Data[8];
				prop_send_by_name("f_clean_mode");
			}

			if(t_d_strength != Data[9]){
				t_d_strength = Data[9];
				prop_send_by_name("t_d_strength");
			}

			if(t_p_strength != Data[10]){
				t_p_strength = Data[10];
				prop_send_by_name("t_p_strength");
			}

			if(f_battery != Data[11]){
				f_battery = Data[11];
				prop_send_by_name("f_battery");
			}

			if(t_sound != Data[12]){
				t_sound = Data[12];
				prop_send_by_name("t_sound");
			}

			if(t_light != Data[13]){
				t_light = Data[13];
				prop_send_by_name("t_light");
			}

			if(ff_error != Data[14]){
				ff_error = Data[14];
				prop_send_by_name("f_error");
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
				prop_send_by_name("f_clean_record");
			}

			AckSendData[0] = CMD;
			AckSendData[1] = 0x00;
			UartSendFormData(AckSendData, 2);
			break;

		case CMDUpLoadMapInfo:
			if((Length - 8) > 512){
				printf("Map Data too length.Length = %d\n", Length - 8);
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
			
			prop_send_by_name("f_realtime_mapinfo");
			
			AckSendData[0] = CMD;
			AckSendData[1] = 0x00;
			UartSendFormData(AckSendData, 2);
			break;

		case CMDUpLoadSumTime:
			if(f_work_time !=( (Data[6] << 8) | Data[7])){
				f_work_time = ((Data[6] << 8) | Data[7]);
				prop_send_by_name("f_work_time");
			}

			if(f_water_box_time != ((Data[8] << 8) | Data[9])){
				f_water_box_time = ((Data[8] << 8) | Data[9]);
				prop_send_by_name("f_water_box_time");
			}

			if(f_dustbin_time != ((Data[10] << 8) | Data[11])){
				f_dustbin_time = ((Data[10] << 8) | Data[11]);
				prop_send_by_name("f_dustbin_time");
			}

			if(f_mul_box_time != ((Data[12] << 8) | Data[13])){
				f_mul_box_time =( (Data[12] << 8) | Data[13]);
				prop_send_by_name("f_mul_box_time");
			}
			AckSendData[0] = CMD;
			AckSendData[1] = 0x00;
			UartSendFormData(AckSendData, 2);
			break;

		case CMDUpLoadFactoryReset:
			if(t_factory_reset != Data[6]){
				t_factory_reset = Data[6];
				prop_send_by_name("t_factory_reset");
			}
			AckSendData[0] = CMD;
			AckSendData[1] = 0x00;
			UartSendFormData(AckSendData, 2);
			break;

		case CMDUpLoadCleanMapInfo:	/* ��ʱû�����Ӧ������ */

			break;

		case CMDUpLoadLifeTime:
			if(f_edge_brush_lifetime != Data[6]){
				f_edge_brush_lifetime = Data[6];
				prop_send_by_name("f_edge_brush_lifetime");
			}

			if(f_roll_brush_lifetime != Data[7]){
				f_roll_brush_lifetime = Data[7];
				prop_send_by_name("f_roll_brush_lifetime");
			}

			if(f_filter_lifetime != Data[8]){
				f_filter_lifetime = Data[8];
				prop_send_by_name("f_filter_lifetime");
			}
			
			if(f_duster_lifetime != Data[9]){
				f_duster_lifetime = Data[9];
				prop_send_by_name("f_duster_lifetime");
			}

			if(f_battery_lifetime != Data[10]){
				f_battery_lifetime = Data[10];
				prop_send_by_name("f_battery_lifetime");
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
				prop_send_by_name("t_timer_0");
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
				prop_send_by_name("t_timer_1");
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
				prop_send_by_name("t_timer_2");
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
				prop_send_by_name("t_timer_3");
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
				prop_send_by_name("t_timer_4");
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
				prop_send_by_name("t_timer_5");
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
				prop_send_by_name("t_timer_6");
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
				prop_send_by_name("t_timer_7");
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
				prop_send_by_name("t_timer_8");
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
				prop_send_by_name("t_timer_9");
				CMDUpLoadAppointmentInfoChange = 0;
			}

			AckSendData[0] = CMD;
			AckSendData[1] = 0x00;
			UartSendFormData(AckSendData, 2);
			break;

		case CMDUpLoadReset:
			if(t_reset_edge_brush != Data[6]){
				t_reset_edge_brush = Data[6];
				prop_send_by_name("t_reset_edge_brush");
			}

			if(t_reset_roll_brush != Data[7]){
				t_reset_roll_brush = Data[7];
				prop_send_by_name("t_reset_roll_brush");
			}

			if(t_reset_filter != Data[8]){
				t_reset_filter = Data[8];
				prop_send_by_name("t_reset_filter");
			}

			if(t_reset_duster != Data[9]){
				t_reset_duster = Data[9];
				prop_send_by_name("t_reset_duster");
			}

			if(t_reset_power != Data[10]){
				t_reset_power = Data[10];
				prop_send_by_name("t_reset_power");
			}

			AckSendData[0] = CMD;
			AckSendData[1] = 0x00;
			UartSendFormData(AckSendData, 2);
			break;

		case CMDUpLoadSearch:
			if(t_search != Data[6]){
				t_search = Data[6];
				prop_send_by_name("t_search");
			}
			AckSendData[0] = CMD;
			AckSendData[1] = 0x00;
			UartSendFormData(AckSendData, 2);
			break;

		case CMDUpLoadControl:
			if(t_control != Data[6]){
				t_control = Data[6];
				prop_send_by_name("t_control");
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

			prop_send_by_name("version");
			
			AckSendData[0] = CMD;
			AckSendData[1] = 0x00;
			UartSendFormData(AckSendData, 2);
			break;

		case CMDUpLoadRealTimeStart:
			f_upload_realmap_starttime[0] = Data[6];	//��
			f_upload_realmap_starttime[2] = Data[7];	//��
			f_upload_realmap_starttime[4] = Data[8];	//��
			f_upload_realmap_starttime[6] = Data[9];	//��
			f_upload_realmap_starttime[8] = Data[10];	//����
			f_upload_realmap_starttime[10] = Data[11];	//ʱ
			f_upload_realmap_starttime[12] = Data[12];	//��
			f_upload_realmap_starttime[14] = Data[13];	//��

			printf("Recv f_upload_realmap_starttime:");
			for(i = 0; i < 16; i++){
				printf("%02x ", f_upload_realmap_starttime[i]);
			}
			printf("\n");
			//������ʱ����
			clock_ints_to_time(&LocalToUTCtime, f_upload_realmap_starttime[0] << 8 | f_upload_realmap_starttime[2], f_upload_realmap_starttime[4], 
				f_upload_realmap_starttime[6], f_upload_realmap_starttime[10], f_upload_realmap_starttime[12], f_upload_realmap_starttime[14]);

			//printf("LocalToUTCtime = %u, %x, %x, %x, %x, %x, %x, %x\n", LocalToUTCtime, f_upload_realmap_starttime[0], f_upload_realmap_starttime[2], f_upload_realmap_starttime[4], f_upload_realmap_starttime[6],f_upload_realmap_starttime[10], f_upload_realmap_starttime[12], f_upload_realmap_starttime[14]);
			LocalToUTCtime = clock_local_to_utc(LocalToUTCtime, 0);
			//printf("LocalToUTCtime = %u\n", LocalToUTCtime);
			clock_fill_details(&clk, LocalToUTCtime);
			//printf("%x, %x, %x, %x, %x, %x, %x\n", clk.year, clk.month, clk.days, clk.day_of_week, clk.hour, clk.min, clk.sec);
			sprintf(&f_upload_realmap_starttime[0], "%02x", ((clk.year >> 8) & 0xFF));	//��
			sprintf(&f_upload_realmap_starttime[2], "%02x", (clk.year & 0xFF));			//��
			sprintf(&f_upload_realmap_starttime[4], "%02x", clk.month);
			sprintf(&f_upload_realmap_starttime[6], "%02x", clk.days);
			sprintf(&f_upload_realmap_starttime[8], "%02x", clk.day_of_week);
			sprintf(&f_upload_realmap_starttime[10], "%02x", clk.hour);
			sprintf(&f_upload_realmap_starttime[12], "%02x", clk.min);
			sprintf(&f_upload_realmap_starttime[14], "%02x", clk.sec);
			prop_send_by_name("f_upload_realmap_starttime");

			AckSendData[0] = CMD;
			AckSendData[1] = 0x00;
			UartSendFormData(AckSendData, 2);
			break;

		case CMDUpLoadRealInfoSwitch:
			if(t_realtime_info != Data[6]){
				t_realtime_info = Data[6];
				prop_send_by_name("t_realtime_info");
			}

			AckSendData[0] = CMD;
			AckSendData[1] = 0x00;
			UartSendFormData(AckSendData, 2);
			break;

		//�·�ָ��
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

		//�豸��ѯָ��
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
			
			prop_send_by_name("t_work_mode");
			prop_send_by_name("t_room_mode");
			prop_send_by_name("f_clean_mode");
			prop_send_by_name("t_d_strength");
			prop_send_by_name("t_p_strength");
			prop_send_by_name("f_battery");
			prop_send_by_name("t_sound");
			prop_send_by_name("t_light");
			prop_send_by_name("f_error");
	
			SendRespondCMD = CMD;
			break;

		case CMDRequeryTimerInfo:
			for(i = 0; i < 5; i++){
				sprintf(&t_timer_0[i*2], "%02x", Data[6 + i]);
			}
			prop_send_by_name("t_timer_0");
			
			for(i = 0; i < 5; i++){
				sprintf(&t_timer_1[i*2], "%02x", Data[11 + i]);
			}
			prop_send_by_name("t_timer_1");
			
			for(i = 0; i < 5; i++){
				sprintf(&t_timer_2[i*2], "%02x", Data[16 + i]);
			}
			prop_send_by_name("t_timer_2");
			
			for(i = 0; i < 5; i++){
				sprintf(&t_timer_3[i*2], "%02x", Data[21 + i]);
			}
			prop_send_by_name("t_timer_3");
			
			for(i = 0; i < 5; i++){
				sprintf(&t_timer_4[i*2], "%02x", Data[26 + i]);
			}
			prop_send_by_name("t_timer_4");
			
			for(i = 0; i < 5; i++){
				sprintf(&t_timer_5[i*2], "%02x", Data[31 + i]);
			}
			prop_send_by_name("t_timer_5");
			
			for(i = 0; i < 5; i++){
				sprintf(&t_timer_6[i*2], "%02x", Data[36 + i]);
			}
			prop_send_by_name("t_timer_6");
			
			for(i = 0; i < 5; i++){
				sprintf(&t_timer_7[i*2], "%02x", Data[41 + i]);
			}
			prop_send_by_name("t_timer_7");
			
			for(i = 0; i < 5; i++){
				sprintf(&t_timer_8[i*2], "%02x", Data[46 + i]);
			}
			prop_send_by_name("t_timer_8");
			
			for(i = 0; i < 5; i++){
				sprintf(&t_timer_9[i*2], "%02x", Data[51 + i]);
			}
			prop_send_by_name("t_timer_9");
			
			SendRespondCMD = CMD;
			break;

		case CMDRequeryLifeTime:
			f_edge_brush_lifetime = Data[6];
			f_roll_brush_lifetime = Data[7];
			f_filter_lifetime = Data[8];
			f_duster_lifetime = Data[9];
			f_battery_lifetime = Data[10];

			prop_send_by_name("f_edge_brush_lifetime");
			prop_send_by_name("f_roll_brush_lifetime");
			prop_send_by_name("f_filter_lifetime");
			prop_send_by_name("f_duster_lifetime");
			prop_send_by_name("f_battery_lifetime");
	
			SendRespondCMD = CMD;
			break;

		case CMDRequeryFWVersion:
			sprintf(MCUFWversion, " fw-%08d", (Data[6]<<24) | (Data[7]<<16) | (Data[8]<<8) | (Data[9]<<0));
			memset(version, 0x00, 64);
			memcpy(version, version_temp, strlen(version_temp));
			strncat(version, MCUFWversion, 12);

			prop_send_by_name("version");
			
			SendRespondCMD = CMD;
			break;

		//ϵͳָ��
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
			NTP_utc = clock_utc();	//��ȡutcʱ��
			NTP_local = clock_local(&NTP_utc);//��ȡ����ʱ��
			clock_fill_details(&clk, NTP_local);
			SendSysNTP(clk, NTP_local);
			//printf("%4.4lu-%2.2u-%2.2uT%2.2u:%2.2u:%2.2u  %2.2u, NTP=%lu, NTP_LOCAL=%lu\n\n",
			//	    clk.year, clk.month, clk.days, clk.hour, clk.min, clk.sec, clk.day_of_week, NTP_utc, NTP_local);
			break;
			
		case CMDSysGetSigQuality:
			adap_net_get_signal(&WifiSignal);	//��ȡ�ź�����
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
			AckSendData[1] = demo_host_version[0];
			AckSendData[2] = demo_host_version[1];
			AckSendData[3] = demo_host_version[2];
			AckSendData[4] = demo_host_version[3];
			AckSendData[5] = demo_host_version[4];
			AckSendData[6] = demo_host_version[5];
			AckSendData[7] = demo_host_version[6];
			AckSendData[8] = demo_host_version[7];

			UartSendFormData(AckSendData, 9);
			printf("SW version:%s", demo_host_version);
			//UartSendFormData(CMDRequerySWVersion, &demo_host_version[0], &Reserve[0], 8);
			break;

		default:
			printf("Recv unknow CMD.\n");
			break;
	}
}
/**************************************************************************************/
/* ���ӻ������Ķ�д�±� */
unsigned char AddRing (unsigned char i)
{
       return (i+1) == SENDBUFFERMAXLEN ? 0 : i+1;
}

/* д���ݵ����λ����� */
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
		printf("Ring Buffer is full.\n");
	}
}

/* �����ݵ����λ����� */
void ReadRingBuffer(void)
{
	unsigned char ReadPos;
	int i;
	int cnt = 0;
	
	if(DataNum > 0)
	{
		ReadPos = R_CurSor;
		/* RingSendBuffer[ReadPos].Data[0]��CMD�ֶ� */
		SendRespondCMD = 0x00;
		while(SendRespondCMD != RingSendBuffer[ReadPos].Data[0]){
			if((cnt%SENDGAPTIME) == 0){
				UartSendFormData(RingSendBuffer[ReadPos].Data, RingSendBuffer[ReadPos].Length);
			}

			if(cnt > SENDCNT){
				printf("Data is Send, But MCU not Respond.CMD = %02x\n", RingSendBuffer[ReadPos].Data[0]);
				break;
			}
			cnt++;
			vTaskDelay(SENDDELAYTIME);
		}
		/* Ӧ���ڴ���������֮�����ƶ����� */
		R_CurSor = AddRing(R_CurSor);
		DataNum--;
	}
	else
	{
		printf("Ring Buffer is empty.\b");
	}
}

/**************************************************************************************/

/* ���ӻ������Ķ�д�±� */
unsigned char AddRingRecv(unsigned char i)
{
       return (i+1) == RECVBUFFERMAXLEN ? 0 : i+1;
}

/* д���ݵ����λ����� */
void WriteRingBufferRecv(unsigned char *Data, unsigned short Len)
{
	if(DataNumRecv < RECVBUFFERMAXLEN)
	{
		RingRecvBuffer[W_CurSorRecv].CMD = Data[5];
		memcpy(RingRecvBuffer[W_CurSorRecv].Data, &Data[0], Len);
		RingRecvBuffer[W_CurSorRecv].Length = Len;

		W_CurSorRecv = AddRingRecv(W_CurSorRecv);
		DataNumRecv++;
		
	}
	else
	{
		printf("Ring Recv Buffer is full.\n");
	}
}

/* �����ݵ����λ����� */
void ReadRingBufferRecv(void)
{
	unsigned char ReadPos;
	int i;
	
	if(DataNumRecv > 0)
	{
		ReadPos = R_CurSorRecv;
		ProtocalUartData(RingRecvBuffer[ReadPos].CMD, RingRecvBuffer[ReadPos].Data, RingRecvBuffer[ReadPos].Length);
		/* Ӧ���ڴ���������֮�����ƶ����� */
		R_CurSorRecv = AddRingRecv(R_CurSorRecv);
		DataNumRecv--;
	}
	else
	{
		printf("Ring Recv Buffer is empty.\b");
	}
}

/**************************************************************************************/
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

/**************************************************************************************/
/* ���� */
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
					/* ����ѭ��buffer */
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
					printf("Recv CRC Error or Frame END Error.Recv CRC=%02x, expect CRC=%02x, Frame END = %02x\n", RecvCRC, CalCRC, RecvCharTemp);

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

/* �ڶ�ʱ��������ã����ܳ�ʱ */
void UartErrorRecvTimeout(void)
{	
	if(UartIrqRecvTimeOut != 0)	
	{		
		UartIrqRecvTimeOut++;	
		if(UartIrqRecvTimeOut > 4)
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

/*************************************�͹��ĺ���*******************************************/
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

/* 100ms��ʱ���ж� */
void timer1_timeout_handler(unsigned int TimeOut)
{
	UartErrorRecvTimeout();

	if(AutoEnterLowpower > 0)
	{
		AutoEnterLowpower++;
		if(AutoEnterLowpower > 40)
		{	/* ����4�뻹û�ж������Զ�����͹��� */
			AutoEnterLowpower = 0;
			releasewakelock();
		}
	}
}

void GpioUartRXIrqCallback (uint32_t id, gpio_irq_event event)
{
	acquirewakelock();
}

void ilife_watchdog_irq_handler(uint32_t id)
{
	printf("!!!!!!watchdog barks!!!!!!\r\n");
	ada_conf_reset(0);
}

void ILIFESweeperInit(void)
{
	gpio_irq_t GpioRXWakeup;
	
	//���ڳ�ʼ��
	serial_init(&sobj,UART_TX,UART_RX);
	serial_baud(&sobj,115200);
	serial_format(&sobj, 8, ParityNone, 1);
	
	serial_irq_handler(&sobj, ILIFEUartIRQ, (uint32_t)&sobj);
	serial_irq_set(&sobj, RxIrq, 1);
	serial_irq_set(&sobj, TxIrq, 1);

	//��ʱ����ʼ��	100ms����һ�ζ�ʱ���ж�
	gtimer_init(&SweeperTimer, TIMER0);
	gtimer_start_periodical(&SweeperTimer, 100000, (void*)timer1_timeout_handler, NULL);

	//gpio��ʼ��
	gpio_irq_init(&GpioRXWakeup, PC_1, GpioUartRXIrqCallback, NULL);
	gpio_irq_set(&GpioRXWakeup, IRQ_FALL, 1);
	gpio_irq_enable(&GpioRXWakeup);
	/* �����߳� */
	xTaskCreate( SendBufferHandler, "SendBufferHandler", 512, NULL, tskIDLE_PRIORITY + 2 + PRIORITIE_OFFSET, NULL );
	/* �����߳� */
	xTaskCreate( RecvBufferHandler, "RecvBufferHandler", 512, NULL, tskIDLE_PRIORITY + 2 + PRIORITIE_OFFSET, NULL );

	//��ʼ�����Ź�
	//watchdog init
	watchdog_init(10000);	//10s
	watchdog_irq_init(ilife_watchdog_irq_handler, 0);
	watchdog_start();
	watchdog_refresh();

	memset(version, 0x00, 64);
	memcpy(version, version_temp, strlen(version_temp));
	printf("SweeperInit OK. version: %s, %s\n", demo_host_version, version);
}

/* �豸��ѯ�ӿ� */
/* ��ѯ�豸״̬��Ϣ */
void RequeryDeviceStatus(void)
{
	unsigned char Data[2] = {0};

	Data[0] = CMDRequeryDeviceStatus;
	Data[1] = 0x00;
	WriteRingBuffer(Data, 2);
}

/* ��ѯԤԼ��Ϣ */
void RequeryTimerInfo(void)
{
	unsigned char Data[2] = {0};

	Data[0] = CMDRequeryTimerInfo;
	Data[1] = 0x00;
	WriteRingBuffer(Data, 2);
}

/* ��ѯ�Ĳ���� */
void RequeryLifeTime(void)
{
	unsigned char Data[2] = {0};

	Data[0] = CMDRequeryLifeTime;
	Data[1] = 0x00;
	WriteRingBuffer(Data, 2);
}

/* ��ѯMCU�̼��汾 */
void RequeryFWVersion(void)
{
	unsigned char Data[2] = {0};

	Data[0] = CMDRequeryFWVersion;
	Data[1] = 0x00;
	WriteRingBuffer(Data, 2);
}

/* ϵͳָ��ӿ� */
/* ����֪ͨ */
void SendNetWorkStatus(unsigned char NetConnetFlag)
{	
	unsigned char Data[3] = {0};
	
	if(NetConnetFlag == 1){				//����
		Data[0] = CMDSysNetWorking;
		Data[1] = 0xF0;
		Data[2] = 0x0F;
	}else{								//����
		Data[0] = CMDSysNetBroken;
		Data[1] = 0xF1;
		Data[2] = 0x1F;
	}
	WriteRingBuffer(Data, 3);
}

/* ����֪ͨ */
void SendCloudStatus(unsigned char CloudStatus)
{
	unsigned char Data[3] = {0};
	
	if(CloudStatus == 1){				//����
		Data[0] = CMDSysCloudWorking;
		Data[1] = 0xF0;
		Data[2] = 0x0F;
	}else{						//����
		Data[0] = CMDSysCloudBroken;
		Data[1] = 0xF1;
		Data[2] = 0x1F;
	}
	WriteRingBuffer(Data, 3);
}

