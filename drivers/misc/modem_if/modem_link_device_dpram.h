/*
 * Copyright (C) 2010 Google, Inc.
 * Copyright (C) 2010 Samsung Electronics.
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */
#include <linux/wakelock.h>

#ifndef __MODEM_LINK_DEVICE_DPRAM_H__
#define __MODEM_LINK_DEVICE_DPRAM_H__

#define DPRAM_ERR_MSG_LEN		128
#define DPRAM_ERR_DEVICE		"dpramerr"

#define MAX_IDX				2

#define DPRAM_BASE_PTR			0x4000000
#define BSP_DPRAM_BASE_SIZE             0x4000	/* 16KB DPRAM */
#define DPRAM_START_ADDRESS		0
#define DPRAM_END_ADDRESS               BSP_DPRAM_BASE_SIZE -1
#define DPRAM_MAGIC_CODE_ADDRESS	DPRAM_START_ADDRESS
#define DPRAM_GOTA_MAGIC_CODE_SIZE		0x4
#define DPRAM_PDA2PHONE_FORMATTED_START_ADDRESS	\
	(DPRAM_START_ADDRESS + DPRAM_GOTA_MAGIC_CODE_SIZE)
//#define BSP_DPRAM_BASE_SIZE		0x1ff8
#define DPRAM_END_OF_ADDRESS		(BSP_DPRAM_BASE_SIZE - 1)
#define DPRAM_INTERRUPT_SIZE		0x2
#define DPRAM_PDA2PHONE_INTERRUPT_ADDRESS	\
	(DPRAM_START_ADDRESS + BSP_DPRAM_BASE_SIZE -  DPRAM_INTERRUPT_SIZE*2)
#define DPRAM_PHONE2PDA_INTERRUPT_ADDRESS	\
	(DPRAM_START_ADDRESS + BSP_DPRAM_BASE_SIZE)
#define DPRAM_BUFFER_SIZE			\
	(DPRAM_PHONE2PDA_INTERRUPT_ADDRESS - DPRAM_PDA2PHONE_FORMATTED_START_ADDRESS)
#define DPRAM_INDEX_SIZE		0x2

#define MAGIC_DMDL			0x4445444C

#define INT_GOTA_MASK_VALID		0xA000
#define MASK_CMD_RECEIVE_READY_NOTIFICATION	0xA100
#define MASK_CMD_DOWNLOAD_START_REQUEST		0xA200
#define MASK_CMD_DOWNLOAD_START_RESPONSE	0xA301
#define MASK_CMD_IMAGE_SEND_REQUEST		0xA400
#define MASK_CMD_IMAGE_SEND_RESPONSE		0xA500
#define MASK_CMD_SEND_DONE_REQUEST		0xA600
#define MASK_CMD_SEND_DONE_RESPONSE		0xA701
#define MASK_CMD_STATUS_UPDATE_NOTIFICATION	0xA800
#define MASK_CMD_UPDATE_DONE_NOTIFICATION	0xA900
#define MASK_CMD_EFS_CLEAR_RESPONSE		0xAB00
#define MASK_CMD_ALARM_BOOT_OK			0xAC00
#define MASK_CMD_ALARM_BOOT_FAIL		0xAD00

#define WRITEIMG_HEADER_SIZE			8
#define WRITEIMG_TAIL_SIZE			4
#define WRITEIMG_BODY_SIZE			\
	(DPRAM_BUFFER_SIZE - WRITEIMG_HEADER_SIZE - WRITEIMG_TAIL_SIZE)

#define DPDN_DEFAULT_WRITE_LEN			WRITEIMG_BODY_SIZE
#define CMD_DL_START_REQ			0x9200
#define CMD_IMG_SEND_REQ			0x9400
#define CMD_DL_SEND_DONE_REQ			0x9600

#define MASK_CMD_RESULT_FAIL			0x0002
#define MASK_CMD_RESULT_SUCCESS			0x0001

#define START_INDEX				0x007F
#define END_INDEX				0x007E

#define CMD_IMG_SEND_REQ			0x9400

#define CRC_TAB_SIZE				256
#define CRC_16_L_SEED				0xFFFF


struct dpram_device {
	/* DPRAM memory addresses */
	u16           *in_head_addr;
	u16           *in_tail_addr;
	u8            *in_buff_addr;
	unsigned long  in_buff_size;

	u16           *out_head_addr;
	u16           *out_tail_addr;
	u8            *out_buff_addr;
	unsigned long  out_buff_size;

	unsigned long  in_head_saved;
	unsigned long  in_tail_saved;
	unsigned long  out_head_saved;
	unsigned long  out_tail_saved;

	u16            mask_req_ack;
	u16            mask_res_ack;
	u16            mask_send;

	char *name;
};

struct dpram_control {
	u16 *magic;
	u16 *access;
	u16 *in_box;
	u16 *out_box;
};
/*
struct memory_region {
	u8 *control;
	u8 *fmt_out;
	u8 *raw_out;
	u8 *fmt_in;
	u8 *raw_in;
	u8 *mbx;
};
*/

struct dpram_link_device {
	struct link_device ld;

		/* maybe -list of io devices for the link device to use
	 * to find where to send incoming packets to */
	
	struct modem_data *pdata;

	/*only dpram*/
	struct wake_lock dpram_wake_lock;
	atomic_t raw_txq_req_ack_rcvd;
	atomic_t fmt_txq_req_ack_rcvd;
	u8 is_net_stopped ;
	int phone_sync;
	u8 phone_status;

	struct work_struct xmit_work_struct;


	/** OTA porting - move new struct
	struct workqueue_struct *gota_wq;
	struct work_struct gota_cmd_work;
	struct dpram_device dev_map[MAX_IDX];
	 */

	/** OTA remove unused variable
	u8 dpram_read_data[131072];
	*/

	int dpram_init_cmd_wait_condition;
	wait_queue_head_t dpram_init_cmd_wait_q;

	int modem_pif_init_wait_condition;
	wait_queue_head_t modem_pif_init_done_wait_q;

	/** OTA Porting
	struct completion gota_download_start_complete;

	int gota_send_done_cmd_wait_condition;
	wait_queue_head_t gota_send_done_cmd_wait_q;

	int gota_update_done_cmd_wait_condition;
	wait_queue_head_t gota_update_done_cmd_wait_q;
	*/
	struct completion update_ack;
	u16 update_ack_cmd;
	unsigned update_ready;

	unsigned int is_dpram_err ;

	char dpram_err_buf[DPRAM_ERR_MSG_LEN];
	struct fasync_struct *dpram_err_async_q;

	void (*clear_interrupt)(struct dpram_link_device *);

	char cpdump_debug_file_name[DPRAM_ERR_MSG_LEN];

	/** OTA porting - remove ...
	struct memory_region m_region;

	unsigned long  fmt_out_buff_size;
	unsigned long  raw_out_buff_size;
	unsigned long  fmt_in_buff_size;
	unsigned long  raw_in_buff_size;
	*/
	struct delayed_work delayed_tx;
	struct sk_buff *delayed_skb;
	u8 delayed_count;

	/** OTA porting
	 new static variables
	 */
	void *shared_base;
	struct dpram_device *dev_map;
	unsigned num_ch;
	struct dpram_control dpctl;

	/** OTA Porting --
	*/
	void (*vendor_clear_irq)(void);
	int (*board_ota_reset)(void);
};
/* converts from struct link_device* to struct xxx_link_device* */
#define to_dpram_link_device(linkdev) \
			container_of(linkdev, struct dpram_link_device, ld)
#endif
