
// Compile String:  gcc -g -O0 -o usbrelay usbrelay.c -lhidapi-libusb // To run: './usbrelay'  (or 'sudo ./usbrelay' if you need other rights)

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>

#include <usb.h>
#include <hid.h>

#include "wmr_wmr.h"
#include "lang/lang_en.h"

/*
typedef union  HIDPacketStruct {
     unsigned char  Data[256];
     struct {
         unsigned char MajorCmd;
         unsigned char MinorCmd;
         unsigned char DataLSB;
         unsigned char DataMSB;
         unsigned char DataHID[4];
         unsigned char DataExt[8];
              } Tx;
      struct {
                unsigned char Cmd;
         } Rx;
        } HIDPacketStruct, *pHIDPacketStruct;
*/

void dump_packet(unsigned char *packet, int len, int syslogEn)
{
    int i;

    sprintf (err_string, WMR_C_TXT_1, len);
    syslog_msg (syslogEn, err_string);
    for(i = 0; i < len; ++i)
    {
	sprintf (err_string, "%02x ", (int)packet[i]);
	syslog_msg (syslogEn, err_string);
    }
    syslog_msg (syslogEn, "\n" );
}

int wmr_send_packet_init(WMR *wmr) {
    int ret;

    ret = hid_set_output_report(wmr->hid, PATH_IN, PATHLEN, (char*)INIT_PACKET1, sizeof(INIT_PACKET1));
    if (ret != HID_RET_SUCCESS) 
    {
	if( wmr->debugEn > 0 )
	{
	    sprintf (err_string, WMR_C_TXT_2, ret);
	    syslog_msg (wmr->syslogEn, err_string);
	}

    return WMR_EXIT_NORMAL;
    }

return WMR_EXIT_SUCCESS;
}

int wmr_send_packet_ready(WMR *wmr) {
    int ret;
    
    ret = hid_set_output_report(wmr->hid, PATH_IN, PATHLEN, (char*)INIT_PACKET2, sizeof(INIT_PACKET2));
    if (ret != HID_RET_SUCCESS) 
    {
	if( wmr->debugEn > 0 )
	{
	    sprintf (err_string, WMR_C_TXT_2, ret);
	    syslog_msg (wmr->syslogEn, err_string);
	}

    return WMR_EXIT_NORMAL;
    }

return WMR_EXIT_SUCCESS;
}

int wmr_init(WMR *wmr) 
{
    hid_return ret;
    HIDInterfaceMatcher matcher = { WMR_VENDOR_ID, WMR_PRODUCT_ID, NULL, NULL, 0 };
    int retries;

    /* see include/debug.h for possible values */
    /*hid_set_debug(HID_DEBUG_ALL);*/
    /*hid_set_debug_stream(stderr);*/
    /* passed directly to libusb */
    /*hid_set_usb_debug(0);*/

    ret = hid_init();
    if (ret != HID_RET_SUCCESS) 
    {
	if( wmr->debugEn > 0 )
	{
	    sprintf (err_string, WMR_C_TXT_4, ret);
	    syslog_msg (wmr->syslogEn, err_string);
	}

    return WMR_EXIT_NORMAL;
    }

    wmr->hid = hid_new_HIDInterface();
    if (wmr->hid == 0) 
    {
	if( wmr->debugEn > 0 )
	{
	    syslog_msg (wmr->syslogEn, WMR_C_TXT_5 );
	}

    return WMR_EXIT_NORMAL;
    }

    retries = 5;
    while(retries > 0) 
    {
        ret = hid_force_open(wmr->hid, 0, &matcher, 10);
	if (ret == HID_RET_SUCCESS) break;

	if( wmr->debugEn > 0 )
	{
	    syslog_msg (wmr->syslogEn, WMR_C_TXT_6 );
	}
	sleep(5);

	--retries;
    }

    if (ret != HID_RET_SUCCESS) 
    {
	if( wmr->debugEn > 0 )
	{
	    sprintf (err_string, WMR_C_TXT_7, ret);
	    syslog_msg (wmr->syslogEn, err_string);
	}

    return WMR_EXIT_NORMAL;
    }

    ret = hid_write_identification(stdout, wmr->hid);
    if (ret != HID_RET_SUCCESS) 
    {
	if( wmr->debugEn > 0 )
	{
	    sprintf (err_string, WMR_C_TXT_8, ret);
	    syslog_msg (wmr->syslogEn, err_string);
	}

    return WMR_EXIT_NORMAL;
    }

    if ( wmr_send_packet_init(wmr) != 0 )  { return WMR_EXIT_NORMAL; }
    if ( wmr_send_packet_ready(wmr) != 0 ) { return WMR_EXIT_NORMAL; }

    return WMR_EXIT_SUCCESS;
}

int wmr_read_packet(WMR *wmr)
{
    int ret, len;

    ret = hid_interrupt_read(wmr->hid,
			     USB_ENDPOINT_IN + 1,
			     (char*)wmr->buffer,
			     RECV_PACKET_LEN,
			     0);

    if (ret != HID_RET_SUCCESS) 
    {
	if( wmr->debugEn > 0 )
	{
	    sprintf (err_string, WMR_C_TXT_9, ret);
	    syslog_msg (wmr->syslogEn, err_string);
	}
	//exit(WMR_EXIT_FAILURE);
	run = RR_WMR_PREEXIT;

    return(WMR_EXIT_FAILURE);
    }
    
    len = wmr->buffer[0];
    if (len > 7) len = 7; /* limit */
    wmr->pos = 1;
    wmr->remain = len;
    
    if( wmr->debugEn > 3 )
    {
	dump_packet(wmr->buffer + 1, wmr->remain, wmr->syslogEn);
    }

return(WMR_EXIT_SUCCESS);
}

int wmr_read_byte(WMR *wmr)
{
    while(wmr->remain == 0) 
    {
	if(wmr_read_packet(wmr) == WMR_EXIT_FAILURE) { return(WMR_EXIT_FAILURE); }
    }
    wmr->remain--;

return wmr->buffer[wmr->pos++];
}

int verify_checksum(unsigned char * buf, int len, int syslogEn, int debugEn ) 
{
    int i, ret = 0, chk;
    for (i = 0; i < len -2; ++i)
    {
	ret += buf[i];
    }
    chk = buf[len-2] + (buf[len-1] << 8);

    if (ret != chk) 
    {
	if( debugEn > 0 )
	{
	    sprintf (err_string, WMR_C_TXT_10, ret, chk);
	    syslog_msg (syslogEn, err_string);
	}

    return WMR_EXIT_FAILURE;
    }

	return WMR_EXIT_SUCCESS;
}

void wmr_read_data(WMR *wmr/*, WEATHER *weather*/)
{
    int i, j, unk1, type, data_len;
    unsigned char *data;

    /* search for 0xff marker */
    i = wmr_read_byte(wmr);
    if ( i == WMR_EXIT_FAILURE) { run = RR_WMR_PREEXIT; return; }

    while(i != 0xff) 
    {
	i = wmr_read_byte(wmr);
    }

    /* search for not 0xff */
    i = wmr_read_byte(wmr);
    while(i == 0xff) 
    {
	i = wmr_read_byte(wmr);
    }
    unk1 = i;

    /* read data type */
    type = wmr_read_byte(wmr);

    /* read rest of data */
    data_len = 0;
    switch(type) 
    {
    case 0x41:
	data_len = 17;
	break;
    case 0x42:
	data_len = 12;
	break;
    case 0x44:
	data_len = 7;
	break;
    case 0x46:
	data_len = 8;
	break;
    case 0x47:
	data_len = 6;
	break;
    case 0x48:
	data_len = 11;
	break;
    case 0x60:
	data_len = 12;
	break;
    default:
	if( wmr->debugEn > 3 )
	{
	    sprintf (err_string, WMR_C_TXT_11, type);
	    syslog_msg (wmr->syslogEn, err_string);
	}
    }

    if (data_len > 0) 
    {
	data = malloc(data_len);
	data[0] = unk1;
	data[1] = type;
	for (j = 2; j < data_len; ++j) 
	{
	    data[j] = wmr_read_byte(wmr);
	}

	if (verify_checksum(data, data_len, wmr->syslogEn, wmr->debugEn) == 0) 
	{
	    get_curtime( &wmr->curtime );
	    //wmr_handle_packet(wmr, weather, data, data_len);
	}

	free(data);
    }

    /* send ack */
    wmr_send_packet_ready(wmr);
}


int main(int argc, char* argv[])
{
     char Port0, Port1;
     int res, count, cmd;
     //hid_device *handle;
     int report_id;
     //HIDPacketStruct MyPacket;

     printf("\n");
     cmd = -1;
         if (argc > 1) {              // Check for command line arguments
         if(isdigit(argv[1][0]) )
             cmd = (int) strtol(argv[1], NULL, 0);
         else      {
             printf("Delcom USB Linux Example. Version 1.0.\n");
             printf("Syntax: tryme [cmd]\n");
             printf("With no arguments, just reads the ports.\n");
             printf("With numeric argument, XORs the value with port1 and write it to port1.\n");
             printf("For example 'tryme 1' will toggle bit 0 on port 1.\n");
             return 1;
         }
     }

    WMR *wmr = NULL;
    wmr = wmr_new();
    if (wmr == NULL) 
    {
		syslog_msg (0,WMR_C_TXT_37);
        //pthread_mutex_unlock(&job_mutex);
		exit(WMR_EXIT_FAILURE);
    }

     // Open the device using the VID, PID,
	 /*
     handle = hid_open(0xfc5, 0xb080, NULL);
     if (!handle) {
         printf("Error: Unable to open device.\n");
          return 1;
     }*/
	 
	if ( wmr_init(wmr) != 0) 
	{
		syslog_msg (0, WMR_C_TXT_23 );
		run = RR_WMR_PREEXIT;
	} else {
		sprintf (err_string, WMR_C_TXT_24, wmr->hid->id);
		syslog_msg (0, err_string);

		// warning: cast from pointer to integer of different size
		//
		wmr_print_state( (unsigned int) wmr->hid, 1 );
		//			wmr_print_state( wmr->hid, 1 );
	}	
	
	 
/*
     // device found, read device info and display
     printf("Delcom Device found. ");
     MyPacket.Rx.Cmd = 10;        // Read Version (Command #10)
     res = hid_get_feature_report(handle, MyPacket.Data, 8);
     if (res < 0) {
         printf("Error: Failed to read device.\n");
         printf("%ls", hid_error(handle));
         return 1;
     }
     else     printf("Firmware Version: %d\n", MyPacket.Data[4]);
*/

     // Read the ports (Command #100).
	 /*
     MyPacket.Rx.Cmd = 100;
     res = hid_get_feature_report(handle, MyPacket.Data, 8);
     if (res < 0) {
         printf("Error: Failed to read device.\n");
         printf("%ls", hid_error(handle));
         return 1;
     }
     else {     // Get and Display the current pin values
         Port0 = MyPacket.Data[0];
         Port1 = MyPacket.Data[1];
         printf("Port0: 0x%02hhx Port1: 0x%02hhx\n", Port0, Port1);
     }*/

	 

     // Now do the write port1 command (if cmd!=-1)
	 /*
     if(cmd!=-1){
         Port1 ^= (char)cmd;        // XOR the port1 value
         printf("Writing value 0x%02hhx to port1.\n",Port1);
         MyPacket.Tx.MajorCmd = 101;    // Write 8 byte command
         MyPacket.Tx.MinorCmd = 2;    // Write to port 1 command
         MyPacket.Tx.DataLSB = Port1;    // Data to write to Port1
         hid_send_feature_report(handle, MyPacket.Data, 8);    // Send it
         }
*/
	wmr_read_data(wmr);

     printf("All done, closing device and HIDAPI objects!\n\n");
     /*
	 hid_close(handle);
     hid_exit();
		*/
	if (wmr != NULL) { wmr_close(wmr); }
	
    return 0;
}