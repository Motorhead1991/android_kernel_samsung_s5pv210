/* /linux/drivers/new_modem_if/link_dev_dpram.c
 *
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

#include <linux/init.h>
#include <linux/irq.h>
#include <linux/gpio.h>
#include <linux/interrupt.h>
#include <linux/timer.h>
#include <linux/wakelock.h>
#include <linux/delay.h>
#include <linux/wait.h>
#include <linux/sched.h>
#include <linux/vmalloc.h>
#include <linux/proc_fs.h>
#include <linux/if_arp.h>
#include <linux/platform_data/modem.h>
#include <linux/crc-ccitt.h>
#include <linux/platform_device.h>
#include "modem_prj.h"
#include "modem_link_device_dpram.h"

#include <linux/platform_data/dpram.h>

#ifdef pr_debug
#undef pr_debug
#define pr_debug pr_err
#endif

#define GOTA_TIMEOUT		(50 * HZ)
#define GOTA_SEND_TIMEOUT	(200 * HZ)

static inline int dpram_readh(void __iomem *p_dest)
{
	unsigned long dest = (unsigned long)p_dest;
	return ioread16(dest);
}

static inline void dpram_writeh(u16 value,  void __iomem *p_dest)
{
	unsigned long dest = (unsigned long)p_dest;
	iowrite16(value, dest);
}

static void dpram_send_interrupt_to_phone(struct dpram_link_device *dpld,
					u16 irq_mask)
{
	dpram_writeh(irq_mask, dpld->dpctl.out_box);
}

static void dpram_clear(struct dpram_link_device *dpld)
{
	unsigned long flags;
	int size = 0;
	int i;

	pr_debug("[DPRAM] *** entering dpram_clear()\n");

	/* clear DPRAM except interrupt area */
	local_irq_save(flags);

	size = DP_HEAD_SIZE + DP_TAIL_SIZE;

	for (i = 0; i < dpld->num_ch; i++) {
		dpld->dev_map[i].in_head_addr = 0;
		dpld->dev_map[i].in_tail_addr = 0;
		dpld->dev_map[i].out_head_addr = 0;
		dpld->dev_map[i].out_tail_addr = 0;
	}
	local_irq_restore(flags);

	pr_debug("[DPRAM] *** leaving dpram_clear()\n");
}

static int dpram_init_and_report(struct dpram_link_device *dpld)
{
	u16 ac_code = 0x0000;
	const u16 init_end = INT_CMD(INT_CMD_INIT_END);
	u16 magic = 0;
	u16 enable = 0;

	/* @LDK@ write DPRAM disable code */
	dpram_writeh(ac_code, dpld->dpctl.access);

	/* @LDK@ dpram clear */
	dpram_clear(dpld);

	/* @LDK@ write magic code */
	dpram_writeh(DP_MAGIC_CODE, dpld->dpctl.magic);

	/* @LDK@ write DPRAM enable code */
	ac_code = 0x0001;
	dpram_writeh(ac_code, dpld->dpctl.access);

	/* @LDK@ send init end code to phone */
	dpram_send_interrupt_to_phone(dpld, init_end);

	magic = dpram_readh(dpld->dpctl.magic);
	enable = dpram_readh(dpld->dpctl.access);

	if (magic != DP_MAGIC_CODE || !enable)
		pr_warn("[DPRAM] magic code = %x, access enable = %x\n",
			magic, enable);

	pr_debug("[DPRAM] Send 0x%x to MailboxBA(Dpram init finish)\n",
			init_end);

	dpld->phone_sync = 1;

	return 0;
}

static void cmd_req_active_handler(struct dpram_link_device *dpld)
{
	dpram_send_interrupt_to_phone(dpld, INT_CMD(INT_CMD_RES_ACTIVE));
}

static void cmd_error_display_handler(struct dpram_link_device *dpld)
{
	char buf[DPRAM_ERR_MSG_LEN] = {0,};

	if (dpld->phone_status) {
		memcpy(dpld->cpdump_debug_file_name,
//				dpld->m_region.fmt_in + 4,
				dpld->dev_map[0].in_buff_addr,
				sizeof(dpld->cpdump_debug_file_name));
	} else {
		/* --- can't catch the CDMA watchdog reset!!*/
		sprintf((void *)buf, "8 $PHONE-OFF");
	}

	memcpy(dpld->dpram_err_buf, buf, DPRAM_ERR_MSG_LEN);
	dpld->is_dpram_err = TRUE;
	kill_fasync(&dpld->dpram_err_async_q, SIGIO, POLL_IN);
}

static void cmd_phone_start_handler(struct dpram_link_device *dpld)
{
	pr_debug("[DPRAM] Received 0xc8 from Phone (Phone Boot OK).\n");
	dpld->dpram_init_cmd_wait_condition = 1;
	wake_up_interruptible(&dpld->dpram_init_cmd_wait_q);
	dpram_init_and_report(dpld);
}

static void cmd_req_time_sync_handler(void)
{
	/* TODO: add your codes here.. */
}

static void cmd_phone_deep_sleep_handler(void)
{
	/* TODO: add your codes here.. */
}

static void cmd_nv_rebuilding_handler(struct dpram_link_device *dpld)
{
	sprintf(dpld->dpram_err_buf, "NV_REBUILDING");
	dpld->is_dpram_err = TRUE;
	kill_fasync(&dpld->dpram_err_async_q, SIGIO, POLL_IN);
}

static void cmd_silent_nv_rebuilding_handler(struct dpram_link_device *dpld)
{
	sprintf(dpld->dpram_err_buf, "SILENT_NV_REBUILDING");
	dpld->is_dpram_err = TRUE;

	kill_fasync(&dpld->dpram_err_async_q, SIGIO, POLL_IN);
}

static void cmd_emer_down_handler(void)
{
	/* TODO: add your codes here.. */
}

static void cmd_pif_init_done_handler(struct dpram_link_device *dpld)
{
	pr_debug("[DPRAM] cmd_pif_init_done_handler\n");
	if (&dpld->modem_pif_init_done_wait_q == NULL) {
		pr_err("[DPRAM] Error - modem_pif_init_done_wait_q is NULL\n");
		return;
	}
	dpld->modem_pif_init_wait_condition = 1;
	pr_debug(" modem_pif_init_wait_condition =%d\n",
		dpld->modem_pif_init_wait_condition);
	wake_up_interruptible(&dpld->modem_pif_init_done_wait_q);
}

static void command_handler(struct dpram_link_device *dpld, u16 cmd)
{
	switch (cmd) {
	case INT_CMD_REQ_ACTIVE:
		cmd_req_active_handler(dpld);
		break;

	case INT_CMD_ERR_DISPLAY:
		cmd_error_display_handler(dpld);
		break;

	case INT_CMD_PHONE_START:
		cmd_phone_start_handler(dpld);
		break;

	case INT_CMD_REQ_TIME_SYNC:
		cmd_req_time_sync_handler();
		break;

	case INT_CMD_PHONE_DEEP_SLEEP:
		cmd_phone_deep_sleep_handler();
		break;

	case INT_CMD_NV_REBUILDING:
		cmd_nv_rebuilding_handler(dpld);
		break;

	case INT_CMD_EMER_DOWN:
		cmd_emer_down_handler();
		break;

	case INT_CMD_PIF_INIT_DONE:
		cmd_pif_init_done_handler(dpld);
		break;

	case INT_CMD_SILENT_NV_REBUILDING:
		cmd_silent_nv_rebuilding_handler(dpld);
		break;

	case INT_CMD_NORMAL_POWER_OFF:
		/*ToDo:*/
		/*kernel_sec_set_cp_ack()*/;
		break;

	default:
		pr_err("Unknown command.. %x\n", cmd);
	}
}

static void dpram_drop_data(struct dpram_device *device)
{
	u16 head = 0;
	u16 tail = 0;

	head = dpram_readh(device->in_head_addr);
	tail = dpram_readh(device->in_tail_addr);

	pr_debug("[DPRAM] %s, head: %d, tail: %d\n", __func__, head, tail);

	if (head >= device->in_buff_size || tail >= device->in_buff_size) {
		head = tail = 0;
		dpram_writeh(head, device->in_head_addr);
	}
	dpram_writeh(head, device->in_tail_addr);
}

static int dpram_read(struct dpram_link_device *dpld,
		struct dpram_device *device, int dev_idx)
{
	struct io_device *iod = NULL;
	int   size = 0, tmp_size = 0;
	u16   head = 0, tail = 0;
	u16   up_tail = 0;
	char *buff = NULL;

	head = dpram_readh(device->in_head_addr);
	tail = dpram_readh(device->in_tail_addr);
	pr_debug("=====> %s,  head: %d, tail: %d\n", __func__, head, tail);

	if (device->in_head_saved == head) {
		pr_err("[DPRAM] device->in_head_saved == head (NO new data)\n");
		goto err_dpram_read;
	}

	if (head == tail) {
		pr_err("[DPRAM] head == tail\n");
		goto err_dpram_read;
	}

	if (tail >= device->in_buff_size || head >= device->in_buff_size) {
		pr_err("[DPRAM] head(%d) or tail(%d) >= buff_size(%lu)\n",
			head, tail, device->in_buff_size);
		goto err_dpram_read;
	}

	list_for_each_entry(iod, &dpld->ld.list_of_io_devices, list) {
		if ((dev_idx == FMT_IDX && iod->format == IPC_FMT) ||
			(dev_idx == RAW_IDX && iod->format == IPC_MULTI_RAW))
			break;
	}
	if (!iod) {
		pr_err("[DPRAM] iod == NULL\n");
		goto err_dpram_read;
	}

	/* Get data size in DPRAM*/
	size = (head > tail) ? (head - tail) :
		(device->in_buff_size - tail + head);

	/* ----- (tail) 7f 00 00 7e (head) ----- */
	if (head > tail) {
		buff = (char *)device->in_buff_addr + tail;
		if (iod->recv(iod, buff, size) < 0)
			dpram_drop_data(device);
		pr_debug("[DPRAM] size : %d\n", size);
	} else { /* 00 7e (head) ----------- (tail) 7f 00 */
		/* 1. tail -> buffer end.*/
		tmp_size = device->in_buff_size - tail;
		buff = (char *)device->in_buff_addr + tail;
		if (iod->recv(iod, buff, tmp_size) < 0)
			dpram_drop_data(device);

		/* 2. buffer start -> head.*/
		if (size > tmp_size) {
			buff = (char *)device->in_buff_addr;
			if (iod->recv(iod, buff, (size - tmp_size)) < 0)
				dpram_drop_data(device);
		}
	}

	/* new tail */
	up_tail = (u16)((tail + size) % device->in_buff_size);
	dpram_writeh(up_tail, device->in_tail_addr);
	pr_debug(" head= %d, tail = %d", head, up_tail);

	device->in_head_saved = head;
	device->in_tail_saved = up_tail;

	return size;

err_dpram_read:
	return -EINVAL;
}

static void non_command_handler(struct dpram_link_device *dpld,
				u16 non_cmd)
{
	struct dpram_device *device = NULL;
	u16 head = 0, tail = 0;
	u16 magic = 0, access = 0;
	int ret = 0;

	pr_debug("[DPRAM] Entering non_command_handler(0x%04X)\n", non_cmd);

	magic = dpram_readh(dpld->dpctl.magic);
	access = dpram_readh(dpld->dpctl.access);

	if (!access || magic != DP_MAGIC_CODE) {
		pr_err("fmr recevie error!!!! phone status =%d, access = 0x%x, magic =0x%x",
				dpld->phone_status, access, magic);
		return;
	}

	/* Check formatted data region */
	device = &dpld->dev_map[FMT_IDX];
	head = dpram_readh(device->in_head_addr);
	tail = dpram_readh(device->in_tail_addr);

	if (head != tail) {
		if (non_cmd & INT_MASK_REQ_ACK_F)
			atomic_inc(&dpld->fmt_txq_req_ack_rcvd);

		ret = dpram_read(dpld, device, FMT_IDX);
		if (ret < 0) {
			pr_err("%s, dpram_read failed\n", __func__);
			/* TODO: ... wrong.. */
		}

		if (atomic_read(&dpld->fmt_txq_req_ack_rcvd) > 0) {
			dpram_send_interrupt_to_phone(dpld,
				INT_NON_CMD(INT_MASK_RES_ACK_F));
			atomic_set(&dpld->fmt_txq_req_ack_rcvd, 0);
		}
	} else {
		if (non_cmd & INT_MASK_REQ_ACK_F) {
			dpram_send_interrupt_to_phone(dpld,
				INT_NON_CMD(INT_MASK_RES_ACK_F));
			atomic_set(&dpld->fmt_txq_req_ack_rcvd, 0);
		}
	}

	/* Check raw data region */
	device = &dpld->dev_map[RAW_IDX];
	head = dpram_readh(device->in_head_addr);
	tail = dpram_readh(device->in_tail_addr);

	if (head != tail) {
		if (non_cmd & INT_MASK_REQ_ACK_R)
			atomic_inc(&dpld->raw_txq_req_ack_rcvd);

		ret = dpram_read(dpld, device, RAW_IDX);
		if (ret < 0) {
			pr_err("%s, dpram_read failed\n", __func__);
			/* TODO: ... wrong.. */
		}

		if (atomic_read(&dpld->raw_txq_req_ack_rcvd) > 0) {
			dpram_send_interrupt_to_phone(dpld,
				INT_NON_CMD(INT_MASK_RES_ACK_R));
			atomic_set(&dpld->raw_txq_req_ack_rcvd, 0);
		}
	} else {
		if (non_cmd & INT_MASK_REQ_ACK_R) {
			dpram_send_interrupt_to_phone(dpld,
				INT_NON_CMD(INT_MASK_RES_ACK_R));
			atomic_set(&dpld->raw_txq_req_ack_rcvd, 0);
		}
	}
}

static irqreturn_t apwakeup_irq_handler(int irq, void *data)
{
	printk("[MODEM_IF] %s - AP_CP_INT(%d), PDA_ACTIVE(%d)\n", __func__, gpio_get_value(GPIO_DPRAM_INT_N), gpio_get_value(GPIO_PDA_ACTIVE));
	return IRQ_HANDLED;
}


static irqreturn_t dpram_irq_handler(int irq, void *p_ld)
{
	u16 irq_mask = 0;
      
	struct link_device *ld = (struct link_device *)p_ld;
	struct dpram_link_device *dpld = to_dpram_link_device(ld);

	irq_mask = dpram_readh(dpld->dpctl.in_box);
	pr_debug("received mailboxAB = 0x%x\n", irq_mask);
    
	/* valid bit verification.
	* or Say something about the phone being dead...*/
	/*
	 * Currnet dpram driver was written for OTA
	 */
	if (!(irq_mask & (INT_GOTA_MASK_VALID)) ||
			irq_mask == INT_POWERSAFE_FAIL)
		goto exit_irq;

	if (irq_mask & INT_GOTA_MASK_VALID) {
		dpld->update_ack_cmd = irq_mask;
		/*if (dpld->update_ack)*/
			complete(&dpld->update_ack);
		/* clear inbox for CP polling*/
	} else if (irq_mask & INT_MASK_CMD) {
		irq_mask &= ~(INT_MASK_VALID | INT_MASK_CMD);
		command_handler(dpld, irq_mask);
	} else {
		irq_mask &= ~INT_MASK_VALID;
		non_command_handler(dpld, irq_mask);
	}

exit_irq:
	dpld->clear_interrupt(dpld);
	return IRQ_HANDLED;
}

static int dpram_attach_io_dev(struct link_device *ld, struct io_device *iod)
{
	struct dpram_link_device *dpld = to_dpram_link_device(ld);

	iod->link = ld;
	/* list up io devices */
	list_add(&iod->list, &dpld->ld.list_of_io_devices);

	return 0;
}

/** OTA Porting
 */
#define DP_UPDATE_TIMEOUT 5000
static int send_cmd_wait_for_ack(struct dpram_link_device *dpld, u16 send_cmd,
	u16 ack_cmd, u16 err_cmd)
{
	int err = -EFAULT, retry_cnt = 5;
		 
	pr_debug("%s: read magic = 0x%x\n", __func__,
			*((unsigned *)dpld->dpctl.magic));
	pr_debug("[MODEM_IF] send=%04x, wait=%04x\n", send_cmd, ack_cmd);
	while (dpld->update_ack_cmd != ack_cmd) {
		init_completion(&dpld->update_ack);
		if (send_cmd)
			dpram_send_interrupt_to_phone(dpld, send_cmd);
		err = wait_for_completion_timeout(&dpld->update_ack,
				DP_UPDATE_TIMEOUT);
		if(!err) {
			pr_err("[MODEM_IF] CP ack timeout");
			if (retry_cnt-- < 0) {
				err = -ETIMEDOUT;
				goto exit;
			}
		}
		if (dpld->update_ack_cmd == err_cmd) {
			pr_err("[MODEM_IF] Got fail nack = 0x%04x\n",
				dpld->update_ack_cmd);
			err = -EFAULT;
			goto exit;
		}
	}
	err = 0;
exit:
	dpld->update_ack_cmd = 0;
	return err;
}

#define DLDRDYNOTIFY                0xA100
#define DLDSTARTREQ                 0x9200
#define DLDSTARTRESP_SUCCESS        0xA301
#define DLDSTARTRESP_FAIL           0xA302
#define DLDIMGSENDREQ               0x9400
#define DLDIMGSENDRESP_SUCCESS      0xA501
#define DLDIMGSENDRESP_FAIL         0xA502
#define DLDIMGSENDDONEREQ           0x9600
#define DLDIMGSENDDONERESP_SUCCESS      0xA701
#define DLDIMGSENDDONERESP_FAIL     0xA702
#define DLDSTATUPDTNOTIFY           0xA800
#define DLDUPDTDONENOTIFY           0xA900

static size_t dpram_update_write(struct dpram_link_device *dpld,
	struct dpram_device *updev, struct sk_buff *skb)
{
	int err = -EFAULT;
	struct cp_update_stat {
		u16 start;
		u16 region;
		u16 percent;
		u16 end;
	} update_states = {0, };

	if (!dpld || !skb || !updev)
		goto exit;

	if (!dpld->update_ready) {
		/* wait 0xA100 */
		pr_err("MODEM_IF send and wait CP Ready CMD\n");
		err = send_cmd_wait_for_ack(dpld, 0, DLDRDYNOTIFY, 0xffff);
		if (err < 0) {
			pr_err("[MODEM_IF] CP update not ready err=%d\n", err);
			goto exit;
		}
		pr_err("MODEM_IF send and wait DOWNLOAD CMD\n");
		/* send 0x9200, wait 0xA301 */
		err = send_cmd_wait_for_ack(dpld, DLDSTARTREQ,
			DLDSTARTRESP_SUCCESS, DLDSTARTRESP_FAIL);
		if (err < 0) {
			pr_err("[MODEM_IF] CP update not ready err=%d\n", err);
			goto exit;
		}
		dpld->update_ready = 1;
		pr_debug("[MODEM_IF] CP Update Ready done\n");
	}

	if (skb->len) {
		memcpy(updev->out_head_addr, skb->data, skb->len);

		/* send 0x9600, wait 0xA701 */
		err = send_cmd_wait_for_ack(dpld, DLDIMGSENDREQ,
			DLDIMGSENDDONERESP_SUCCESS, DLDIMGSENDDONERESP_FAIL);
		if (err < 0) {
			pr_err("[MODEM_IF] CP SEND ack fail err=%d\n", err);
			goto exit;
		}
	} else {
		/* send 0xA600, wait 0xA701*/
		err = send_cmd_wait_for_ack(dpld, DLDIMGSENDDONEREQ,
			DLDIMGSENDDONERESP_SUCCESS, DLDIMGSENDDONERESP_FAIL);
		if (err < 0) {
			pr_err("[MODEM_IF] CP SEND DONE ack fail err=%d\n", err);
			goto exit;
		}
		/* check the CP update status */
		memcpy(&update_states, updev->out_head_addr,
			sizeof(struct cp_update_stat));
		pr_err("[MODEM_IF] update  start = 0x%04x, end = 0x%04x\n",
			update_states.start, update_states.end);
		pr_err("[MODEM_IF] update  region = 0x%04x, per = %d\%\n",
			update_states.region, update_states.percent);
	}
	dev_kfree_skb_any(skb);

	return 0;
exit:
	return err;

}

static int dpram_write(struct dpram_link_device *dpld,
			struct dpram_device *device,
			const unsigned char *buf,
			int len)
{
	u16   head = 0, tail = 0, up_head = 0;
	u16 irq_mask = 0;
	int free_space = 0;
	int last_size = 0;

	head = dpram_readh(device->out_head_addr);
	tail = dpram_readh(device->out_tail_addr);

	free_space = (head < tail) ? tail - head - 1 :
			device->out_buff_size + tail - head - 1;
	if (len > free_space) {
		pr_err("WRITE: No space in Q\n");
		pr_err("len[%d] free_space[%d] head[%u] tail[%u] out_buff_size =%lu\n",
			len, free_space, head, tail, device->out_buff_size);
		return -EINVAL;
	}

	pr_debug("WRITE: len[%d] free_space[%d] head[%u] tail[%u] out_buff_size =%lu\n",
			len, free_space, head, tail, device->out_buff_size);

	pr_debug("%s, head: %d, tail: %d\n", __func__, head, tail);
	if (head < tail) {
		/* +++++++++ head ---------- tail ++++++++++ */
		memcpy((device->out_buff_addr + head), buf, len);
	} else {
		/* ------ tail +++++++++++ head ------------ */
		last_size = device->out_buff_size - head;
		memcpy((device->out_buff_addr + head), buf,
			len > last_size ? last_size : len);
		if (len > last_size) {
			memcpy(device->out_buff_addr, (buf + last_size),
				(len - last_size));
		}
	}

	/* Update new head */
	up_head = (u16)((head + len) % device->out_buff_size);
	dpram_writeh(up_head, device->out_head_addr);

	device->out_head_saved = up_head;
	device->out_tail_saved = tail;

	irq_mask = INT_MASK_VALID;

	if (len > 0)
		irq_mask |= device->mask_send;

	dpram_send_interrupt_to_phone(dpld, irq_mask);

	return len;
}

/*
* dpram_stop_netif_queue stops all of netdevice under this driver's control
*/
static void dpram_stop_netif_queue(struct dpram_link_device *dpld)
{
	int i;
	struct io_device *iod;
	struct io_device *real_iod;
	struct io_raw_devices *io_raw_devs;

	list_for_each_entry(iod, &dpld->ld.list_of_io_devices, list) {
		if (iod->format == IPC_MULTI_RAW)
			break;
	}
	if (iod->format != IPC_MULTI_RAW) {
		pr_err("%s: there's no multi raw device\n", __func__);
		return;
	}
	io_raw_devs = (struct io_raw_devices *)iod->private_data;

	for (i = 0 ; i < MAX_RAW_DEVS; i++) {
		real_iod = io_raw_devs->raw_devices[i];
		if (real_iod == NULL)
			continue;
		if (real_iod->io_typ == IODEV_NET)
			if (real_iod->ndev)
				netif_stop_queue(real_iod->ndev);
	}
}

/*
* dpram_wake_netif_queue starts all of netdevice under this driver's control
*/
static void dpram_wake_netif_queue(struct dpram_link_device *dpld)
{
	int i;
	struct io_device *iod;
	struct io_device *real_iod;
	struct io_raw_devices *io_raw_devs;

	list_for_each_entry(iod, &dpld->ld.list_of_io_devices, list) {
		if (iod->format == IPC_MULTI_RAW)
			break;
	}

	if (iod->format != IPC_MULTI_RAW) {
		pr_err("%s: there's no multi raw device\n", __func__);
		return;
	}

	io_raw_devs = (struct io_raw_devices *)iod->private_data;

	for (i = 0 ; i < MAX_RAW_DEVS; i++) {
		real_iod = io_raw_devs->raw_devices[i];
		if (real_iod == NULL)
			continue;
		if (real_iod->io_typ == IODEV_NET)
			if (real_iod->ndev)
				netif_wake_queue(real_iod->ndev);
	}
}

static void dpram_delayed_write(struct work_struct *work)
{
	int ret;
	int idx;
	struct io_device *iod;
	struct dpram_link_device *dpld =
		container_of(work, struct dpram_link_device, delayed_tx.work);
	struct sk_buff *skb = dpld->delayed_skb;

	if (!skb)
		return;
	iod = *((struct io_device **)skb->cb);

	if (iod->format == IPC_FMT)
		idx = FMT_IDX;
	else
		idx = RAW_IDX;

	ret = dpram_write(dpld, &dpld->dev_map[idx], skb->data, skb->len);
	if (ret < 0) {
		if (dpld->delayed_count++ > 10) {
			pr_err("%s: delayed write failed over 10 times\n",
								__func__);
			dev_kfree_skb_any(skb);
			dpld->delayed_count = 0;
			dpld->delayed_skb = NULL;
			return;
		}
		schedule_delayed_work(&dpld->delayed_tx, msecs_to_jiffies(10));
	} else {
		dpld->delayed_count = 0;
		dpld->delayed_skb = NULL;
		dpram_wake_netif_queue(dpld);
		dev_kfree_skb_any(skb);
	}

	return;
}

static int dpram_send(struct link_device *ld, struct io_device *iod,
	struct sk_buff *skb)
{
	struct dpram_link_device *dpld = to_dpram_link_device(ld);
	struct dpram_device *device = NULL;
	int ret;

	switch (iod->format) {
	pr_debug(" %s iod->format = %d\n", __func__, iod->format);
	case IPC_FMT:
		device = &dpld->dev_map[FMT_IDX];
		break;
	case IPC_RAW:
		device = &dpld->dev_map[RAW_IDX];
		break;
	case IPC_UPDATE:
		device = &dpld->dev_map[UPDATE_IDX];
		return dpram_update_write(dpld, device, skb);

	case IPC_BOOT:
	case IPC_RFS:
	default:
		device = NULL;
		return 0;
	}

	ret = dpram_write(dpld, device, skb->data, skb->len);
	/*
	* add error handling here and remember waiting skb in private data
	* run dpram space free work to restart transmission
	*/
	if (ret < 0) {
		*((struct io_device **)skb->cb) = iod;
		dpld->delayed_skb = skb;
		dpld->delayed_count = 0;
		schedule_delayed_work(&dpld->delayed_tx, msecs_to_jiffies(10));
		/* stop all net if */
		dpram_stop_netif_queue(dpld);
		/*
		* return success,because delayed work will handle currenc packet
		* and all net device interface has already stopped
		*/
		return 0;
	}

	dev_kfree_skb_any(skb);

	return ret;
}
void clear_dpram_memory(struct link_device *ld)
{
    int i=0;
	struct dpram_link_device *dpld = to_dpram_link_device(ld);

	pr_err("[DPRAM]clear_dpram_memory\n");
	/* DPRAM Clear.. */
	for ( i = DPRAM_START_ADDRESS; i <= DPRAM_END_OF_ADDRESS; i ++)
		*((u8 *)dpld->shared_base + i) = 0;

}
void clear_irq_form_cp(struct dpram_link_device *dpld)
{
	u16 in_interrupt = 0;
	memcpy((void *)&in_interrupt, dpld->dpctl.in_box, sizeof(in_interrupt));

	if (dpld->vendor_clear_irq)
		dpld->vendor_clear_irq();

}

u16 calc_total_frame(u32 nDividend, u16 nDivisor)
{
	u16 nCompVal1 = 0;
	u16 nCompVal2 = 0;

	nCompVal1 = (u16)(nDividend / nDivisor);
	nCompVal2 = (u16)(nDividend  - (nCompVal1 * nDivisor));

	if (nCompVal2 > 0)
		nCompVal1++;

	return nCompVal1;
}

static int dpram_link_ioctl(struct link_device *ld, struct io_device *iod,
	unsigned cmd, unsigned long _arg)
{
	int err = -EFAULT;
	struct dpram_link_device *dpld = to_dpram_link_device(ld);
	unsigned dl_magic = MAGIC_DMDL;

	pr_debug("%s: link_device ioctl cmd = 0x%08x\n", __func__, cmd);

	switch (cmd) {
	case IOCTL_MODEM_GOTA_START:
		pr_debug("%s: IOCTL_MODEM_GOTA_START\n", __func__);
                dpld->update_ready=0;
		dpld->board_ota_reset();
		memcpy(dpld->dpctl.magic, &dl_magic, sizeof(unsigned));
		pr_debug("%s: read magic = 0x%x\n", __func__,
			*((unsigned *)dpld->dpctl.magic));
		break;
	default:
		break;
	}
	return 0;
exit:
	return err;
}

static void init_shared_channel_table(struct dpram_link_device *dpld,
	struct dpram_device *init_dev, struct modemlink_shared_channel *init_ch)
{
	char *bi = dpld->shared_base + init_ch->in_offset;
	char *bo = dpld->shared_base + init_ch->out_offset;

	init_dev->in_head_addr = (u16 *)bi;
	init_dev->in_tail_addr = (u16 *)(bi + DP_HEAD_SIZE);
	init_dev->in_buff_addr = (u8 *)(bi + DP_HEAD_SIZE + DP_TAIL_SIZE);
	init_dev->in_buff_size = init_ch->in_size;
	init_dev->out_head_addr = (u16 *)bo;
	init_dev->out_tail_addr = (u16 *)(bo + DP_HEAD_SIZE);
	init_dev->out_buff_addr = (u8 *)(bo + DP_HEAD_SIZE + DP_TAIL_SIZE);
	init_dev->out_buff_size = init_ch->out_size;

	init_dev->mask_req_ack = INT_MASK_REQ_ACK_F;
	init_dev->mask_res_ack = INT_MASK_RES_ACK_F;
	init_dev->mask_send = INT_MASK_SEND_F;

	init_dev->name = init_ch->name;
}

static int if_dpram_init(struct platform_device *pdev, struct link_device *ld)
{
	int ret = 0;
	int i;
	unsigned irq;
	struct resource *res;

	struct dpram_link_device *dpld = to_dpram_link_device(ld);
	struct modem_data *pdata =
			(struct modem_data *)pdev->dev.platform_data;
	struct modemlink_memmap *smmap =
			(struct modemlink_memmap *)pdata->modemlink_extension;

	dpld->is_dpram_err = FALSE;
	strcpy(&dpld->cpdump_debug_file_name[0], "CDMA Crash");
	wake_lock_init(&dpld->dpram_wake_lock, WAKE_LOCK_SUSPEND, "DPRAM");

	init_waitqueue_head(&dpld->modem_pif_init_done_wait_q);

	/* map the shard bank channels */
	dpld->num_ch = smmap->num_shared_map;
	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	if (!res) {
		pr_err("[DPRAM]failed to get shard map io\n");
		return -EINVAL;
	}
	dpld->shared_base = (u8 *)ioremap_nocache(res->start,
			res->end - res->start + 1);
	if (!dpld->shared_base) {
		pr_err("[DPRAM]failed ioremap\n");
		return -EINVAL;
	}
	pr_debug("dpram base phy=%x, vir=%x\n", res->start, dpld->shared_base);

	dpld->dev_map =
		kzalloc(dpld->num_ch * sizeof(struct dpram_device), GFP_KERNEL);
	if (!dpld->dev_map)
		return -ENOMEM;

	for (i = 0; i < dpld->num_ch; i++) {
		pr_debug("[dpram] Initailize dpram table - %s\n",
			smmap->shared_map[i].name);
		init_shared_channel_table(dpld, &dpld->dev_map[i],
			&smmap->shared_map[i]);
	}
	dpld->dpctl.magic = (u16 *)(dpld->shared_base + smmap->magic_offset);
	dpld->dpctl.access = (u16 *)(dpld->shared_base + smmap->access_offset);
	dpld->dpctl.in_box = (u16 *)(dpld->shared_base + smmap->in_box_offset);
	dpld->dpctl.out_box = (u16 *)(dpld->shared_base + smmap->out_box_offset);

	dpld->board_ota_reset = smmap->board_ota_reset;
	init_waitqueue_head(&dpld->dpram_init_cmd_wait_q);
	init_completion(&dpld->update_ack);

	atomic_set(&dpld->raw_txq_req_ack_rcvd, 0);
	atomic_set(&dpld->fmt_txq_req_ack_rcvd, 0);

	INIT_WORK(&dpld->xmit_work_struct, NULL);
	INIT_DELAYED_WORK(&dpld->delayed_tx, dpram_delayed_write);

	/* register dpram irq */

	/** OTA Porting
	  Move the platform specition data to arch/arm/mach-
	ld->irq = IRQ_DPRAM_INT_N;
	 Internal dpram can't support wakeup source, HW use AP wake-up GPIO, and
	 it is different with External DPRAM wake enable handling
	 */
	if (pdata->gpio_ap_wakeup) {
		/* for S.LSI internal dpram only*/
		dpld->vendor_clear_irq = smmap->vendor_clear_irq;

		/* Internal Dpram*/
		irq = gpio_to_irq(pdata->gpio_ap_wakeup);
		if (irq < 0) {
			pr_err("[MODEM_IF] ap wkaeup gpio_to_irq fail err=%d\n",
				irq);
			goto exit;
		}
		pr_debug("[MODEM_IF] get ap_wakeup irq =%d\n", irq);

		ret = request_irq(irq, apwakeup_irq_handler,
			IRQ_TYPE_EDGE_RISING, "ap wakeup", ld);
		if (ret) {
			pr_err("[MODEM_IF] get ap wakeup irq fail err=%d\n",
				ret);
			goto exit;
		}
		#ifdef MODEM_IF_DEBUG_STMTS
		else pr_err("[MODEM_IF] passed gpio_ap_wakeup request_irq:%d \n" ,irq);
		#endif	
		
		ret = enable_irq_wake(irq);
		if (ret < 0) {
			pr_err("DPRAM wake register fail err = %d\n", ret);
			goto exit;
		}

		#ifdef MODEM_IF_DEBUG_STMTS
        	else pr_err("[MODEM_IF] passed gpio_ap_wakeup enable_irq_wake:%d\n" , ret);
		#endif	
		

		ld->irq = platform_get_irq_byname(pdev, "dpram_irq");
		pr_debug("[MODEM_IF] get irq from platform device = %d\n",
			ld->irq);
		dpld->clear_interrupt(dpld);
		ret = request_irq(ld->irq, dpram_irq_handler, IRQF_DISABLED, "dpram irq", ld);
		if (ret) {
			pr_err("DPRAM interrupt handler failed err=%d\n", ret);
			goto exit;
		}
		#ifdef MODEM_IF_DEBUG_STMTS
		else pr_err("[MODEM_IF] passed to dpram_irq request_irq:%d return value:%d \n" ,ld->irq, ret);
		#endif	
	

	} else {
	/* External Dpram*/
		/*TODO: register dpram EINT irq*/
		ret = set_irq_type(ld->irq, IRQ_TYPE_EDGE_FALLING);
		if (ret < 0) {
			pr_err("DPRAM interrupt setting fail err = %d\n", ret);
			goto exit;
		}
		ret = enable_irq_wake(ld->irq);
		if (ret < 0) {
			pr_err("DPRAM wake register fail err = %d\n", ret);
			goto exit;
		}
	}

	pr_debug("[DPRAM] if_dpram_init() done : %d\n", ret);
exit:
	return ret;
}

struct link_device *dpram_create_link_device(struct platform_device *pdev)
{
	int ret;
	struct dpram_link_device *dpld;
	struct link_device *ld;
	struct modem_data *pdata;

	pdata = pdev->dev.platform_data;

	dpld = kzalloc(sizeof(struct dpram_link_device), GFP_KERNEL);
	if (!dpld)
		return NULL;

	INIT_LIST_HEAD(&dpld->ld.list_of_io_devices);
	skb_queue_head_init(&dpld->ld.sk_fmt_tx_q);
	skb_queue_head_init(&dpld->ld.sk_raw_tx_q);

	ld = &dpld->ld;
	dpld->pdata = pdata;

	ld->name = "dpram";
	ld->attach = dpram_attach_io_dev;
	ld->send = dpram_send;
	ld->ioctl = dpram_link_ioctl;
        ld->clear_link_device_memory = clear_dpram_memory;
	dpld->clear_interrupt = clear_irq_form_cp;

	ret = if_dpram_init(pdev, ld);
	if (ret)
		return NULL;

	pr_debug("[MODEM_IF] %s : create_io_device DONE\n", dpld->ld.name);
	return ld;
}
