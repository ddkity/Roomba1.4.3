/*
 * Copyright 2011 Ayla Networks, Inc.  All rights reserved.
 *
 * Use of the accompanying software is permitted only in accordance
 * with and subject to the terms of the Software License Agreement
 * with Ayla Networks, Inc., a copy of which can be obtained from
 * Ayla Networks, Inc.
 */
#ifndef __AYLA_SPI_H__
#define __AYLA_SPI_H__

#include <ayla/exti.h>
#if defined(ARCH_stm32f2)
#include <stm32f2xx.h>
#include <stm32f2xx_usart.h>
#include <stm32f2xx_rcc.h>
#include <stm32f2xx_conf.h>
#elif defined(ARCH_stm32f4)
#include <stm32f4xx.h>
#include <stm32f4xx_usart.h>
#include <stm32f4xx_rcc.h>
#include <stm32f4xx_conf.h>
#endif /* stm32f2 || stm32f4 */

enum spi_op_intrs {
	SI_DONT_BLOCK,
	SI_BLOCK
};

enum spi_state {
	SPI_ST_IDLE,		/* not transferring */
	SPI_ST_RX,		/* doing RX Non-DMA */
	SPI_ST_TX,		/* doing TX Non-DMA */
	SPI_ST_RX_DMA,		/* doing RX DMA */
	SPI_ST_TX_DMA,		/* doing TX DMA */
	SPI_ST_RX_DONE,		/* RX DMA complete */
	SPI_ST_TX_DONE,		/* TX DMA complete */
};

struct spi_port {
	SPI_TypeDef *port;	/* registers */
	DMA_TypeDef *dma;	/* DMA registers, if used */
	DMA_Stream_TypeDef *dma_rx;	/* DMA RX Stream */
	DMA_Stream_TypeDef *dma_tx;	/* DMA Tx Stream */
	u32	dma_channel;	/* DMA Channel */
	u32	rcc_spi;	/* RCC mask to enable the SPI bus */
	u32	rcc_dma;	/* RCC mask to enable DMA */
	void (*rcc_clkcmd)(uint32_t, FunctionalState);
	void (*rcc_clklpmodecmd)(uint32_t, FunctionalState);
	u16	irq_pin_id;	/* pin id for irq */
	u16	miso_pin_id;	/* miso pin id */
	u16	mosi_pin_id;	/* mosi pin id */
	u16	sck_pin_id;	/* sck pin id */
	u16	sel_pin_id;	/* sel pin id */
	enum spi_op_intrs spi_op_intrs;	/* to/not block irqs during spi ops */
	enum spi_state spi_state;	/* current state of spi dev */
	IRQn_Type dma_rx_irq;	/* RX IRQn */
	IRQn_Type dma_tx_irq;	/* TX IRQn */
	u8	af_selection;	/* AF Selection */
};

const struct spi_port *spi_init(u32 dev_index,
	    void (*irq_handler)(struct exti_handler *, u16), u8 speed);
void spi_send_cmd(u32 dev, const u8 *txbuf, ssize_t tx_len,
		u8 *rxbuf, ssize_t rx_len);
void spi_send_cmd2(u32 dev, const u8 *buf1, size_t len1,
		const u8 *buf2, size_t len2);
void spi_send_cmd_nosel(u32 dev_index, const u8 *tx_buf, ssize_t tx_len,
	u8 *rx_buf, ssize_t rx_len);
void spi_select(const struct spi_port *spi);
void spi_deselect(const struct spi_port *spi);
u8 spi_io(const struct spi_port *spi, u8 data);
void spi_intr_mask(const struct spi_port *spi, int enable);

#endif /* __AYLA_SPI_H__ */
