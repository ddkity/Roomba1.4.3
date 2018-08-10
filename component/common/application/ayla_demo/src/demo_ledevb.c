/*
 * Copyright 2017 Ayla Networks, Inc.  All rights reserved.
 */

/*
 * Ayla device agent demo of a simple lights and buttons evaluation board
 * using the "simple" property manager.
 *
 * The property names are chosen to be compatible with the Ayla Control
 * App.  E.g., the LED property is Blue_LED even though the color is yellow.
 * Button1 sends the Blue_button property, even though the button is white.
 */
#define HAVE_UTYPES
#include "lwip/ip_addr.h"

#include <ayla/utypes.h>
#include <ayla/log.h>
#include <sys/types.h>
#include <ada/libada.h>
#include <ada/sprop.h>
#include <ada/task_label.h>
#include "conf.h"
#include "demo.h"
#include "ilifesweeper.h"

#define BUILD_PROGNAME "ILIFESWEEPER"
/***************************************************************
	1.0.4	解决报错:[ada] 01:56:30.988 W s ssl: [218]TLS:2 err=-0x7200
	1.0.5	切换到了智意ayla的中国量产域
	1.0.6	更改oem model为ilife-0-0
	1.0.7	1、添加log查看当模组掉线的时候是因为什么掉线的。2、在首次上电的时候会忽略自动更新的属性，之后有自动更新属性的也不会忽略，防止丢失属性设置
	1.1.0	给t_work_mode做一个判断，如果在刚上电的时候就操作工作模式，也让它有响应
	1.1.1	加快获取扫地机状态的速度
	1.1.2	修改获取属性状态值得更新时间间隔
	1.1.3	在上传属性状态的时候，t_work_mode都要上传的
	1.1.4	修复t_work_mode属性无法上传的bug，同时把f_error的属性改为to device的方式
	1.1.5	不判断是否注册设备
	1.1.6	电池电量每10秒钟更新一次
	1.1.7	修改发送联网状态的时间
	1.1.8	增加判断更新所有属性的接口
	1.1.9	修改恢复出厂之后等一秒钟再重启设置，保证离线的信息能够发到扫地机
	2.0.0	修改恢复出厂设置的时候的操作
	2.0.1	增加在设备更新时区的时候，把时间信息发送到扫地机
	2.0.2	把每10秒钟上传一次电池电量的功能给去掉了
***************************************************************/
#define BUILD_VERSION "2.0.2"
#define BUILD_STRING	BUILD_VERSION " "  __DATE__ " " __TIME__

//const char mod_sw_build[] = BUILD_STRING;
//const char mod_sw_version[] = BUILD_PROGNAME " " BUILD_STRING;

/* oem相关的定义 */
SECTION(".sdram.data")  char oem[] = DEMO_OEM_ID;
SECTION(".sdram.data")  char oem_model[] = DEMO_ILIFE_MODEL;

SECTION(".sdram.data") char version_temp[] = BUILD_PROGNAME " " BUILD_STRING;
SECTION(".sdram.data") char version[64] = {0};
SECTION(".sdram.data") char demo_host_version[] = "ilife-03-no-lan";	/* property template version */

SECTION(".sdram.data") char MCUFWversion[12] = " fw-00000000";

/* 属性变量的定义 */
SECTION(".sdram.data") int t_work_mode = 0;
SECTION(".sdram.data") int t_room_mode = 0;
SECTION(".sdram.data") int t_d_strength = 0;
SECTION(".sdram.data") int t_p_strength = 0;
SECTION(".sdram.data") int t_control = 0;
SECTION(".sdram.data") unsigned char t_search = 0;
SECTION(".sdram.data") unsigned char t_reset_edge_brush = 0;
SECTION(".sdram.data") unsigned char t_reset_roll_brush = 0;
SECTION(".sdram.data") unsigned char t_reset_filter = 0;
SECTION(".sdram.data") unsigned char t_reset_duster = 0;
SECTION(".sdram.data") unsigned char t_reset_power = 0;
SECTION(".sdram.data") unsigned char t_sound = 0;
SECTION(".sdram.data") unsigned char t_light = 0;
SECTION(".sdram.data") unsigned char t_factory_reset = 0;
SECTION(".sdram.data") unsigned char t_realtime_info = 0; 

SECTION(".sdram.data") unsigned char t_timer_0[11] = {0};
SECTION(".sdram.data") unsigned char t_timer_1[11] = {0};
SECTION(".sdram.data") unsigned char t_timer_2[11] = {0};
SECTION(".sdram.data") unsigned char t_timer_3[11] = {0};
SECTION(".sdram.data") unsigned char t_timer_4[11] = {0};
SECTION(".sdram.data") unsigned char t_timer_5[11] = {0};
SECTION(".sdram.data") unsigned char t_timer_6[11] = {0};
SECTION(".sdram.data") unsigned char t_timer_7[11] = {0};
SECTION(".sdram.data") unsigned char t_timer_8[11] = {0};
SECTION(".sdram.data") unsigned char t_timer_9[11] = {0};

//from device
SECTION(".sdram.data") int f_clean_mode = 0;
SECTION(".sdram.data") int f_battery = 0;
SECTION(".sdram.data") int ff_error = 0;
SECTION(".sdram.data") int f_edge_brush_lifetime = 0;
SECTION(".sdram.data") int f_roll_brush_lifetime = 0;
SECTION(".sdram.data") int f_filter_lifetime = 0;
SECTION(".sdram.data") int f_duster_lifetime = 0;
SECTION(".sdram.data") int f_battery_lifetime = 0;
SECTION(".sdram.data") int f_work_time = 0;
SECTION(".sdram.data") int f_water_box_time = 0;
SECTION(".sdram.data") int f_dustbin_time = 0;
SECTION(".sdram.data") int f_mul_box_time  = 0;
SECTION(".sdram.data") unsigned char f_clean_record[17] = {0};
SECTION(".sdram.data") unsigned char f_upload_realmap_switch = 0;
SECTION(".sdram.data") unsigned char f_upload_realmap_starttime[17] = {0};
SECTION(".sdram.data") unsigned char f_realtime_mapinfo[686] = {0};

/* 临时属性变量 */
SECTION(".sdram.data") unsigned char f_clean_record_temp[17] = {0};
SECTION(".sdram.data") unsigned char t_timer_temp[11] = {0};

/* 网络标志 */
extern unsigned char ILITE_NetConnetFlag;	//网络连接标志，1表示连接上了路由，0表示没有连接到路由

/* 网络准备好了，下发的属性才能有效，否则丢弃当前下发的属性值，防止在设备的时候下发属性 */
SECTION(".sdram.data") unsigned char NetIsReady = 0;
SECTION(".sdram.data") unsigned char UpdatePropertyFlag = 0;	/* 属性更新标志，用于设置只有在上电联网首次更新所有属性的时候忽略的标志 */

SECTION(".sdram.data") unsigned char  PropertySendDoneFlag[43] = {0};	/* 属性发送完成标志 */
SECTION(".sdram.data") unsigned char FactoryResetFlag = 0;	/* 恢复出厂标志 */

static enum ada_err t_onedata_property_set(struct ada_sprop *sprop, const void *buf, size_t len)
{
	int ret;
	unsigned char Data[2] = {0};

	acquirewakelock();
	if(sprop->name == "t_work_mode"){
		ret = ada_sprop_set_int(sprop, buf, len);
		if (ret) {
			return ret;
		}
		Data[0] = CMDDownWorkMode;
		Data[1] = t_work_mode & 0xFF;
	}else if(sprop->name == "t_room_mode"){
		ret = ada_sprop_set_int(sprop, buf, len);
		if (ret) {
			return ret;
		}
		Data[0] = CMDDownRoomMode;
		Data[1] = t_room_mode & 0xFF;
	}else if(sprop->name == "t_control"){
		ret = ada_sprop_set_int(sprop, buf, len);
		if (ret) {
			return ret;
		}
		Data[0] = CMDDownControl;
		Data[1] = t_control & 0xFF;
	}else if(sprop->name == "t_search"){
		ret = ada_sprop_set_bool(sprop, buf, len);
		if (ret) {
			return ret;
		}
		Data[0] = CMDDownSearch;
		Data[1] = t_search & 0xFF;
	}else if(sprop->name == "t_factory_reset"){
		ret = ada_sprop_set_bool(sprop, buf, len);
		if (ret) {
			return ret;
		}
		//Data[0] = CMDDownFactoryReset;
		//Data[1] = t_factory_reset & 0xFF;
	}else if(sprop->name == "t_realtime_info"){
		ret = ada_sprop_set_bool(sprop, buf, len);
		if (ret) {
			return ret;
		}
		Data[0] = CMDDownupRealtimeInfo;
		Data[1] = t_realtime_info & 0xFF;	
	}else if(sprop->name == "f_error"){
		ret = ada_sprop_set_int(sprop, buf, len);
		if (ret) {
			return ret;
		}
		log_put(LOG_INFO "%s set to %d.This is ignore property\n", sprop->name, *(u8 *)sprop->val);
		return AE_OK;
	}else{
		log_put(LOG_ERR "t_onedata_property_set ERROR.\n");
		return AE_OK;
	}
	
	log_put(LOG_INFO "%s set to %d.\n", sprop->name, *(u8 *)sprop->val);

	if((NetIsReady != 1) || (UpdatePropertyFlag != 1) || (1 != g_first_get_cmds)){
		log_put(LOG_INFO "ignore property %s\n", sprop->name);
		return AE_OK;
	}

	if(sprop->name == "t_factory_reset"){
		FactoryResetFlag = 1;
		return AE_OK;
	}
	
	WriteRingBuffer(Data, 2);
	return AE_OK;
}

static enum ada_err t_twodata_property_set(struct ada_sprop *sprop, const void *buf, size_t len)
{
	int ret;
	unsigned char Data[3] = {0};

	acquirewakelock();
	if(sprop->name == "t_d_strength" || sprop->name == "t_p_strength"){
		ret = ada_sprop_set_int(sprop, buf, len);
		if (ret) {
			return ret;
		}
		Data[0] = CMDDownCleanStrength;
		Data[1] = t_d_strength & 0xFF;
		Data[2] = t_p_strength & 0xFF;
	}else if(sprop->name == "t_sound" || sprop->name == "t_light"){
		ret = ada_sprop_set_bool(sprop, buf, len);
		if (ret) {
			return ret;
		}
		Data[0] = CMDDownDisturb;
		Data[1] = t_sound & 0xFF;
		Data[2] = t_light & 0xFF;
	}else{
		log_put(LOG_INFO "t_twodata_property_set ERROR.\n");
		return -19;
	}

	log_put(LOG_INFO "%s set to %d.\n", sprop->name, *(u8 *)sprop->val);
	if((NetIsReady != 1) || (UpdatePropertyFlag != 1) || (1 != g_first_get_cmds)){
		log_put(LOG_INFO "ignore property %s\n", sprop->name);
		return AE_OK;
	}
	
	WriteRingBuffer(Data, 3);
	return AE_OK;
}

static enum ada_err t_fivedata_property_set(struct ada_sprop *sprop, const void *buf, size_t len)
{
	int ret = 0;
	unsigned char Data[6] = {0};

	acquirewakelock();
	ret = ada_sprop_set_bool(sprop, buf, len);
	if (ret) {
		return ret;
	}
	Data[0] = CMDDownReset;
	Data[1] = t_reset_edge_brush & 0xFF;
	Data[2] = t_reset_roll_brush & 0xFF;
	Data[3] = t_reset_filter & 0xFF;
	Data[4] = t_reset_duster & 0xFF;
	Data[5] = t_reset_power & 0xFF;
	
	log_put(LOG_INFO "%s set to %d.\n", sprop->name, *(u8 *)sprop->val);
	if((NetIsReady != 1) || (UpdatePropertyFlag != 1) || (1 != g_first_get_cmds)){
		log_put(LOG_INFO "ignore property %s\n", sprop->name);
		return AE_OK;
	}
	
	WriteRingBuffer(Data, 6);
	return AE_OK;
}

//两个字符两个字符组成一个字节
static void StringToHex(unsigned char *Des, unsigned char *Src, unsigned short Len)
{
 	int value[2] = {0};
	int i;

	for(i = 0; i < Len*2; i++)
	{
		if(*Src >= '0' && *Src <= '9'){
			value[i%2] = *Src - '0';
		}else if(*Src >= 'a' && *Src <= 'f'){
			value[i%2] = *Src - 'a' + 10;
		}else if(*Src >= 'A' && *Src <= 'F'){
			value[i%2] = *Src - 'A' + 10;
		}else{
			break;	//不是有效的数据，或者数据已经接收完成了，退出
		}

		if((i%2) == 1){
			Des[i/2] = value[0]*16 + value[1];
			value[0] = '\0';
			value[1] = '\0';
		}
		Src++;
	}
}

static enum ada_err t_timer_set(struct ada_sprop *sprop,
				const void *buf, size_t len)
{
	int ret;

	unsigned char Data[5] = {0};
	unsigned char SendData[51] = {0};	//存放10条预约信息

	acquirewakelock();
	ret = ada_sprop_set_string(sprop, buf, len);
	if (ret) {
		return ret;
	}
	SendData[0] = CMDDownTimer;
	
	StringToHex(Data, t_timer_0, 5);
	memcpy(&SendData[1], Data, 5);
	memset(Data, 0x00, 5);
	
	StringToHex(Data, t_timer_1, 5);
	memcpy(&SendData[6], Data, 5);
	memset(Data, 0x00, 5);

	StringToHex(Data, t_timer_2, 5);
	memcpy(&SendData[11], Data, 5);
	memset(Data, 0x00, 5);

	StringToHex(Data, t_timer_3, 5);
	memcpy(&SendData[16], Data, 5);
	memset(Data, 0x00, 5);

	StringToHex(Data, t_timer_4, 5);
	memcpy(&SendData[21], Data, 5);
	memset(Data, 0x00, 5);

	StringToHex(Data, t_timer_5, 5);
	memcpy(&SendData[26], Data, 5);
	memset(Data, 0x00, 5);

	StringToHex(Data, t_timer_6, 5);
	memcpy(&SendData[31], Data, 5);
	memset(Data, 0x00, 5);

	StringToHex(Data, t_timer_7, 5);
	memcpy(&SendData[36], Data, 5);
	memset(Data, 0x00, 5);

	StringToHex(Data, t_timer_8, 5);
	memcpy(&SendData[41], Data, 5);
	memset(Data, 0x00, 5);
	
	StringToHex(Data, t_timer_9, 5);
	memcpy(&SendData[46], Data, 5);
	memset(Data, 0x00, 5);
	
	log_put(LOG_INFO "%s set to %s.\n", sprop->name, (u8 *)sprop->val);
	if((NetIsReady != 1) || (UpdatePropertyFlag != 1) || (1 != g_first_get_cmds)){
		log_put(LOG_INFO "ignore property %s\n", sprop->name);
		return AE_OK;
	}
	
	WriteRingBuffer(SendData, 51);
	return AE_OK;
}


SECTION(".sdram.data")  struct ada_sprop demo_props[] = {
	{ "oem_host_version", ATLV_UTF8, demo_host_version, sizeof(demo_host_version), ada_sprop_get_string, NULL},
	{ "version", ATLV_UTF8, version, sizeof(version), ada_sprop_get_string, NULL},
	//to device
	 { "t_work_mode", ATLV_INT, &t_work_mode, sizeof(t_work_mode), ada_sprop_get_int, t_onedata_property_set},
	{ "t_room_mode", ATLV_INT, &t_room_mode, sizeof(t_room_mode), ada_sprop_get_int, t_onedata_property_set},
	{ "t_control", ATLV_INT, &t_control, sizeof(t_control), ada_sprop_get_int, t_onedata_property_set},
	{ "t_search", ATLV_BOOL, &t_search, sizeof(t_search), ada_sprop_get_bool, t_onedata_property_set },
	{ "t_factory_reset", ATLV_BOOL, &t_factory_reset, sizeof(t_factory_reset), ada_sprop_get_bool, t_onedata_property_set },
	{ "t_realtime_info", ATLV_BOOL, &t_realtime_info, sizeof(t_realtime_info), ada_sprop_get_bool, t_onedata_property_set},    
	{ "t_d_strength", ATLV_INT, &t_d_strength, sizeof(t_d_strength), ada_sprop_get_int, t_twodata_property_set},	    
	{ "t_p_strength", ATLV_INT, &t_p_strength, sizeof(t_p_strength), ada_sprop_get_int, t_twodata_property_set},
	{ "t_sound", ATLV_BOOL, &t_sound, sizeof(t_sound), ada_sprop_get_bool, t_twodata_property_set },
	{ "t_light", ATLV_BOOL, &t_light, sizeof(t_light), ada_sprop_get_bool, t_twodata_property_set },
	{ "t_reset_edge_brush", ATLV_BOOL, &t_reset_edge_brush, sizeof(t_reset_edge_brush), ada_sprop_get_bool, t_fivedata_property_set },
	{ "t_reset_roll_brush", ATLV_BOOL, &t_reset_roll_brush, sizeof(t_reset_roll_brush), ada_sprop_get_bool, t_fivedata_property_set },
	{ "t_reset_filter", ATLV_BOOL, &t_reset_filter, sizeof(t_reset_filter), ada_sprop_get_bool, t_fivedata_property_set },
	{ "t_reset_duster", ATLV_BOOL, &t_reset_duster, sizeof(t_reset_duster), ada_sprop_get_bool, t_fivedata_property_set },
	{ "t_reset_power", ATLV_BOOL, &t_reset_power, sizeof(t_reset_power), ada_sprop_get_bool, t_fivedata_property_set },
	{ "t_timer_0", ATLV_UTF8, &t_timer_0[0], sizeof(t_timer_0), ada_sprop_get_string, t_timer_set },
	{ "t_timer_1", ATLV_UTF8, &t_timer_1[0], sizeof(t_timer_1), ada_sprop_get_string, t_timer_set },
	{ "t_timer_2", ATLV_UTF8, &t_timer_2[0], sizeof(t_timer_2), ada_sprop_get_string, t_timer_set },
	{ "t_timer_3", ATLV_UTF8, &t_timer_3[0], sizeof(t_timer_3), ada_sprop_get_string, t_timer_set },
	{ "t_timer_4", ATLV_UTF8, &t_timer_4[0], sizeof(t_timer_4), ada_sprop_get_string, t_timer_set },
	{ "t_timer_5", ATLV_UTF8, &t_timer_5[0], sizeof(t_timer_5), ada_sprop_get_string, t_timer_set },
	{ "t_timer_6", ATLV_UTF8, &t_timer_6[0], sizeof(t_timer_6), ada_sprop_get_string, t_timer_set },
	{ "t_timer_7", ATLV_UTF8, &t_timer_7[0], sizeof(t_timer_7), ada_sprop_get_string, t_timer_set },
	{ "t_timer_8", ATLV_UTF8, &t_timer_8[0], sizeof(t_timer_8), ada_sprop_get_string, t_timer_set },
	{ "t_timer_9", ATLV_UTF8, &t_timer_9[0], sizeof(t_timer_9), ada_sprop_get_string, t_timer_set },
	//from device
	{ "f_clean_mode", ATLV_INT, &f_clean_mode, sizeof(f_clean_mode), ada_sprop_get_int, NULL },
	{ "f_battery", ATLV_INT, &f_battery, sizeof(f_battery), ada_sprop_get_int, NULL },
	{ "f_error", ATLV_INT, &ff_error, sizeof(ff_error), ada_sprop_get_int, t_onedata_property_set },
	{ "f_edge_brush_lifetime", ATLV_INT, &f_edge_brush_lifetime, sizeof(f_edge_brush_lifetime), ada_sprop_get_int, NULL },
	{ "f_roll_brush_lifetime", ATLV_INT, &f_roll_brush_lifetime, sizeof(f_roll_brush_lifetime), ada_sprop_get_int, NULL },
	{ "f_filter_lifetime", ATLV_INT, &f_filter_lifetime, sizeof(f_filter_lifetime), ada_sprop_get_int, NULL },
	{ "f_duster_lifetime", ATLV_INT, &f_duster_lifetime, sizeof(f_duster_lifetime), ada_sprop_get_int, NULL },
	{ "f_battery_lifetime", ATLV_INT, &f_battery_lifetime, sizeof(f_battery_lifetime), ada_sprop_get_int, NULL },
	{ "f_work_time", ATLV_INT, &f_work_time, sizeof(f_work_time), ada_sprop_get_int, NULL },
	{ "f_water_box_time", ATLV_INT, &f_water_box_time, sizeof(f_water_box_time), ada_sprop_get_int, NULL },
	{ "f_dustbin_time", ATLV_INT, &f_dustbin_time, sizeof(f_dustbin_time), ada_sprop_get_int, NULL },
	{ "f_mul_box_time", ATLV_INT, &f_mul_box_time, sizeof(f_mul_box_time), ada_sprop_get_int, NULL },
	{ "f_upload_realmap_switch", ATLV_BOOL, &f_upload_realmap_switch, sizeof(f_upload_realmap_switch), ada_sprop_get_bool, NULL },
	{ "f_clean_record", ATLV_UTF8, &f_clean_record[0], sizeof(f_clean_record), ada_sprop_get_string, NULL },
	{ "f_upload_realmap_starttime", ATLV_UTF8, &f_upload_realmap_starttime[0], sizeof(f_upload_realmap_starttime), ada_sprop_get_string, NULL },
	{ "f_realtime_mapinfo", ATLV_UTF8, &f_realtime_mapinfo[0], sizeof(f_realtime_mapinfo), ada_sprop_get_string, NULL },
};

/* 用于属性上传状态查看 */
void PrintPropSendDoneFlag(void)
{
	printf("timer_0\ttimer_1\ttimer_2\ttimer_3\ttimer_4\ttimer_5\ttimer_6\ttimer_7\ttimer_8\ttimer_9\n");
	printf("%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\n", PropertySendDoneFlag[PP_t_timer_0], PropertySendDoneFlag[PP_t_timer_1], \
		PropertySendDoneFlag[PP_t_timer_2], PropertySendDoneFlag[PP_t_timer_3], PropertySendDoneFlag[PP_t_timer_4], \
		PropertySendDoneFlag[PP_t_timer_5], PropertySendDoneFlag[PP_t_timer_6], PropertySendDoneFlag[PP_t_timer_7], \
		PropertySendDoneFlag[PP_t_timer_8], PropertySendDoneFlag[PP_t_timer_9]);
	
	printf("edge_lifetime\troll_lifetime\tfilter_lifetime\tduster_lifetime\tbattery_lifetime\tclean_record\tfactory_reset\n");
	printf("%d\t\t%d\t\t%d\t\t%d\t\t%d\t\t\t%d\t\t%d\n", PropertySendDoneFlag[PP_f_edge_brush_lifetime], PropertySendDoneFlag[PP_f_roll_brush_lifetime], \
		PropertySendDoneFlag[PP_f_filter_lifetime], PropertySendDoneFlag[PP_f_duster_lifetime], PropertySendDoneFlag[PP_f_battery_lifetime], \
		PropertySendDoneFlag[PP_f_clean_record], PropertySendDoneFlag[PP_t_factory_reset]);

	printf("f_battery\thost_version\tversion\twork_mode\tt_control\tt_search\troom_mode\n");
	printf("%d\t\t%d\t\t%d\t\t%d\t\t%d\t\t%d\t\t%d\n", PropertySendDoneFlag[PP_f_battery], PropertySendDoneFlag[PP_oem_host_version], PropertySendDoneFlag[PP_version], \
		PropertySendDoneFlag[PP_t_work_mode],	PropertySendDoneFlag[PP_t_control], PropertySendDoneFlag[PP_t_search], PropertySendDoneFlag[PP_t_room_mode]);

	printf("realtime_mapinfo\trealtime_info\trealmap_starttime\twork_time\twater_box_time\tdustbin_time\tmul_box_time\tupload_realmap_switch\n");
	printf("%d\t\t%d\t\t%d\t%d\t\t%d\t\t%d\t\t%d\t\t%d\n", PropertySendDoneFlag[PP_f_realtime_mapinfo], PropertySendDoneFlag[PP_t_realtime_info], \
		PropertySendDoneFlag[PP_f_upload_realmap_starttime], PropertySendDoneFlag[PP_f_work_time], \
		PropertySendDoneFlag[PP_f_water_box_time], PropertySendDoneFlag[PP_f_dustbin_time], \
		PropertySendDoneFlag[PP_f_mul_box_time], PropertySendDoneFlag[PP_f_upload_realmap_switch]);

	printf("f_error\tf_clean_mode\td_strength\tp_strength\tt_sound\tt_light\n");
	printf("%d\t\t%d\t\t%d\t\t%d\t\t%d\t\t%d\n", PropertySendDoneFlag[PP_f_error], PropertySendDoneFlag[PP_f_clean_mode], \
		PropertySendDoneFlag[PP_t_d_strength], PropertySendDoneFlag[PP_t_p_strength], \
		PropertySendDoneFlag[PP_t_sound], PropertySendDoneFlag[PP_t_light]);

	print("reset_edge_brush\treset_roll_brush\treset_filter\treset_duster\treset_power\n");
	printf("%d\t\t\t%d\t\t%d\t\t%d\t\t%d\n", PropertySendDoneFlag[PP_t_reset_edge_brush], PropertySendDoneFlag[PP_t_reset_roll_brush], \
		PropertySendDoneFlag[PP_t_reset_filter], PropertySendDoneFlag[PP_t_reset_duster], PropertySendDoneFlag[PP_t_reset_power]);
}

/*****************************
*	上报属性的接口 
*	参数1:属性名
*	参数2:属性对应的位置
******************************/
void prop_send_by_name(const char *name, enum PropPost PropPost)
{
	enum ada_err err;

	if((strcmp(name, "version") == 0) || (strcmp(name, "oem_host_version") == 0)){
		goto SendByNAME;
	}

	if((ILITE_NetConnetFlag != 1) || ((ada_sprop_dest_mask & NODES_ADS) != 1) || (g_first_get_cmds != 1)){
		return;
	}else{
		goto SendByNAME;
	}
		
SendByNAME:
	//vTaskSuspendAll();
	PropertySendDoneFlag[PropPost] = PropertySendDoneFlag[PropPost] + 1;
	//xTaskResumeAll();
	
	err = ada_sprop_send_by_name(name);
	if (err) {
		log_put(LOG_INFO "demo: %s: send of %s: err %d",
		    __func__, name, err);
	}
}

/* 属性测试用 */
#if 0
void TestProp(void){
		prop_send_by_name("oem_host_version", PP_oem_host_version);
		prop_send_by_name("version", PP_version);
		prop_send_by_name("t_work_mode", PP_t_work_mode);
		prop_send_by_name("t_room_mode", PP_t_room_mode);
		prop_send_by_name("t_control", PP_t_control);
		prop_send_by_name("t_search", PP_t_search);
		prop_send_by_name("t_factory_reset", PP_t_factory_reset);
		prop_send_by_name("t_realtime_info", PP_t_realtime_info);
		prop_send_by_name("t_d_strength", PP_t_d_strength);
		prop_send_by_name("t_p_strength", PP_t_p_strength);
		prop_send_by_name("t_sound", PP_t_sound);
		prop_send_by_name("t_light", PP_t_light);
		prop_send_by_name("t_reset_edge_brush", PP_t_reset_edge_brush);
		prop_send_by_name("t_reset_roll_brush", PP_t_reset_roll_brush);
		prop_send_by_name("t_reset_filter", PP_t_reset_filter);
		prop_send_by_name("t_reset_duster", PP_t_reset_duster);
		prop_send_by_name("t_reset_power", PP_t_reset_power);
		prop_send_by_name("t_timer_0", PP_t_timer_0);
		prop_send_by_name("t_timer_1", PP_t_timer_1);
		prop_send_by_name("t_timer_2", PP_t_timer_2);
		prop_send_by_name("t_timer_3", PP_t_timer_3);
		prop_send_by_name("t_timer_4", PP_t_timer_4);
		prop_send_by_name("t_timer_5", PP_t_timer_5);
		prop_send_by_name("t_timer_6", PP_t_timer_6);
		prop_send_by_name("t_timer_7", PP_t_timer_7);
		prop_send_by_name("t_timer_8", PP_t_timer_8);
		prop_send_by_name("t_timer_9", PP_t_timer_9);
		prop_send_by_name("f_clean_mode", PP_f_clean_mode);
		prop_send_by_name("f_battery", PP_f_battery);
		prop_send_by_name("f_error", PP_f_error);
		prop_send_by_name("f_edge_brush_lifetime", PP_f_edge_brush_lifetime);
		prop_send_by_name("f_roll_brush_lifetime", PP_f_roll_brush_lifetime);
		prop_send_by_name("f_filter_lifetime", PP_f_filter_lifetime);
		prop_send_by_name("f_duster_lifetime", PP_f_duster_lifetime);
		prop_send_by_name("f_battery_lifetime", PP_f_battery_lifetime);
		prop_send_by_name("f_work_time", PP_f_work_time);
		prop_send_by_name("f_water_box_time", PP_f_water_box_time);
		prop_send_by_name("f_dustbin_time", PP_f_dustbin_time);
		prop_send_by_name("f_mul_box_time", PP_f_mul_box_time);
		prop_send_by_name("f_upload_realmap_switch", PP_f_upload_realmap_switch);
		prop_send_by_name("f_clean_record", PP_f_clean_record);
		prop_send_by_name("f_upload_realmap_starttime", PP_f_upload_realmap_starttime);
		prop_send_by_name("f_realtime_mapinfo", PP_f_realtime_mapinfo);
}
#endif

#define RESETCMT_NOP (0)
#define RESETCMT_END (1)
SECTION(".sdram.data") unsigned char RESETCMTStatus = RESETCMT_NOP;

unsigned char FactoryResetFunc(void)
{
	unsigned char ret = 1;
	
	switch(RESETCMTStatus)
	{
		case RESETCMT_NOP:
			PropertySendDoneFlag[PP_t_factory_reset] = 0;
			//初始化timer
			memcpy(t_timer_0, "0100000000", 10);
			memcpy(t_timer_1, "0200000000", 10);
			memcpy(t_timer_2, "0300000000", 10);
			memcpy(t_timer_3, "0400000000", 10);
			memcpy(t_timer_4, "0500000000", 10);
			memcpy(t_timer_5, "0600000000", 10);
			memcpy(t_timer_6, "0700000000", 10);
			memcpy(t_timer_7, "0800000000", 10);
			memcpy(t_timer_8, "0900000000", 10);
			memcpy(t_timer_9, "0a00000000", 10);
			prop_send_by_name("t_timer_0", PP_t_timer_0);
			prop_send_by_name("t_timer_1", PP_t_timer_1);
			prop_send_by_name("t_timer_2", PP_t_timer_2);
			prop_send_by_name("t_timer_3", PP_t_timer_3);
			prop_send_by_name("t_timer_4", PP_t_timer_4);
			prop_send_by_name("t_timer_5", PP_t_timer_5);
			prop_send_by_name("t_timer_6", PP_t_timer_6);
			prop_send_by_name("t_timer_7", PP_t_timer_7);
			prop_send_by_name("t_timer_8", PP_t_timer_8);
			prop_send_by_name("t_timer_9", PP_t_timer_9);

			//初始化清扫记录
			memcpy(f_clean_record, "ffffffffffffffff", 16);
			prop_send_by_name("f_clean_record", PP_f_clean_record);

			//初始化耗材寿命
			f_edge_brush_lifetime = 0x64;
			f_roll_brush_lifetime = 0x64;
			f_filter_lifetime = 0x64;
			f_duster_lifetime = 0x64;
			f_battery_lifetime = 0x64;
			prop_send_by_name("f_edge_brush_lifetime", PP_f_edge_brush_lifetime);
			prop_send_by_name("f_roll_brush_lifetime", PP_f_roll_brush_lifetime);
			prop_send_by_name("f_filter_lifetime", PP_f_filter_lifetime);
			prop_send_by_name("f_duster_lifetime", PP_f_duster_lifetime);
			prop_send_by_name("f_battery_lifetime", PP_f_battery_lifetime);

			t_factory_reset = 0;
			prop_send_by_name("t_factory_reset", PP_t_factory_reset);
			RESETCMTStatus = RESETCMT_END;
			ret = 1;
			
			log_put(LOG_INFO "FactoryResetFunc Send prop.\n");
			
			break;

		case RESETCMT_END:
			if(PropertySendDoneFlag[PP_t_factory_reset] == 0){
				ret = 0;
				RESETCMTStatus = RESETCMT_NOP;
			}else{
				ret = 1;
			}
			break;
			
		default:
			ret = 1;
			break;
	}
        return ret;
}

void demo_init(void)
{
	ada_sprop_mgr_register("ledevb", demo_props, ARRAY_LEN(demo_props));
}

SECTION(".sdram.data") unsigned int TimeCnt = 0;	/* 时间计数器，用于每10分钟上传一次属性，同步设备时间 */
void demo_idle(void)
{
	char PropertySendOK = 0;	/* 设备已经更新属性标志 */
	char NetworkUp = 0;	/* 联网完成标志 */
	unsigned char Data[2] = {0};
	
	log_thread_id_set(TASK_LABEL_DEMO);
	taskstat_dbg_start();

	memset(&PropertySendDoneFlag[0], 0x00, sizeof(PropertySendDoneFlag));
	/* 上传host version和version */
	memset(version, 0x00, 64);
	memcpy(version, version_temp, strlen(version_temp));
	prop_send_by_name("oem_host_version", PP_oem_host_version);
	prop_send_by_name("version", PP_version);
	
	while (1) {
		vTaskDelay(100);
		
		TimeCnt++;
		if(TimeCnt > 6000)		/* 10分钟更新一次，为了同步时间 */
		{
			prop_send_by_name("f_battery", PP_f_battery);
			TimeCnt = 0;
		}

		/* 联云联网成功 */
		if((ILITE_NetConnetFlag == 1) && (ada_sprop_dest_mask & NODES_ADS) && (g_first_get_cmds == 1))
		{
			if(PropertySendOK == 0)
			{
				vTaskDelay(200);
				RequeryFWVersion();
				vTaskDelay(200);
				RequeryDeviceStatus();
				vTaskDelay(200);
				RequeryTimerInfo();
				vTaskDelay(200);
				RequeryLifeTime();
				
				vTaskDelay(200);	//属性更新完成之后才显示联网成功，然后允许下发其他属性
				SendNetWorkStatus(1);
				vTaskDelay(200);
				SendCloudStatus(1);
				PropertySendOK = 1;
			}
			
			NetworkUp = 1;
			NetIsReady = 1;
			UpdatePropertyFlag = 1;
		}
		else
		{
			PropertySendOK = 0;
			if((NetworkUp == 1))
			{
				/* 添加log信息，查看当掉线的时候是什么原因导致的 */
				log_put(LOG_INFO "ILITE_NetConnetFlag = %d, (ada_sprop_dest_mask & NODES_ADS) = %d, ada_conf.reg_user = %d\n", ILITE_NetConnetFlag, (ada_sprop_dest_mask & NODES_ADS), ada_conf.reg_user);
				NetworkUp = 0;
				vTaskDelay(100);
				SendNetWorkStatus(0);
				vTaskDelay(100);
				SendCloudStatus(0);
			}
			NetIsReady = 0;
			g_first_get_cmds = 0;
		}

		/* 检测到有恢复出厂设置 */
		if(1 == FactoryResetFlag){
			if((FactoryResetFunc() == 0) || (ada_conf.reg_user == 0)){
				FactoryResetFlag = 0;
				//发送恢复出厂给扫地机，然后擦除wifi信息
				Data[0] = CMDDownFactoryReset;
				Data[1] = 0x01;
				WriteRingBuffer(Data, 2);
			}
		}

		if(g_TimezoneChange == 1){
			log_put(LOG_INFO "Set Time to ilife Sweeper.\n");
			SentNTPToSweeper();
			g_TimezoneChange = 0;
		}
	}
}

