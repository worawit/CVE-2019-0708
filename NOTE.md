# CVE-2019-0708 (BlueKeep)

This BlueKeep exploitation note is for Windows 7 and Windows Server 2008.

- Link that provided some internal struct of RDP.
https://support.microsoft.com/en-us/help/2867446/how-to-enable-a-third-party-driver-to-intercept-and-disable-the-sas-ke
- There are 6 channel classes (Keyboard, Mouse, Video, Beep, Command and Virtual) on a RDP server. Only Virtual channel class has 32 channels.
- Normally each channel has its own thread for reading/parsing channel data. When reading data from channel.
- A RDP server also has a thread for receiving network data from client. This thread also does parsing packets then dispatch to handler functions.
- When there is a RDP request that needed to pass data to a channel, the server will check if there is a pending channel read IRP in queue.
  - If there is a pending queue, the receiver thread will copy channel data to request buffer then call IoCompleteRequest.
  - If there is no pending queue, the channel data will be copied and stored in channel buffer linked list (in ```termdd!IcaChannelInputInternal```).
- The channel buffer linked list struct is
    ```c
    struct {
        list   _LIST_ENTRY
        pdata  PVOID // pointer to channel data at the end of struct
        // ... other members
    }
    ```
- Normally we control the RIP with from indirect call instruction ```call [reg]```
  - The channel buffer ```pdata``` address can be used for indirect call to start of channel data
- No need spraying nonpaged pool with full shellcode. When sending data to freed MS_T120 channel (trigger USE and code execution), a full shellcode can be in sent as channel data.
  - When jumping to staging shellcode, copy the full shellcode to nonpaged memory.
  - Staging shellcode can be very small. my size for x64 is 13 bytes (8 bytes is possible too).

**Note:** Available channels before authentication are Keyboard, Mouse, Beep, Command, MS_T120, CTXTW, RDPDR, RDPSND

### Nonpaged pool spraying with RDPSND channel
- Maximum channel data size is 1600 bytes.
- Can use RDP 4.0 bulk compression to quick spray.
  - maximum decompressed data size is 8192 bytes while maximum compressed data size is still 1600 bytes.
- From my guess, RDPSND channel never get read because the channel is for sending sound to play on client only.
- RDPSND channel is disabled by default on Windows 2008 R2 (fDisabledCam=1). The channel is created then removed immediately.

### RDPSND channel detection
- Use "Ease of Access" button on bottom left
- Sound data will be sent to client over RDPSND channel
  - Required "fDisableCam=0" and "Windows Audio Service" is running
  - Without "Windows Audio Service" service, RDPSND is usable but cannot be detected with this method

### Nonpaged pool spraying with RDPDR channel
- If target is single processor (such as VM) and big data is sent to a RDPDR channel very fast, you might see the target keep allocating nonpaged pool memory. That becauses a server CPU is busy receiving data and creating channel buffer (no time to process data).
- Sending invalid RDPDR packet causes server close RDPDR channel
  - A server will drop channel data if channel is closed or invalid
- The thread for reading RDPDR channel can be blocked if the send buffer is full while replying
  - So sending many RDPDR requests but no reading response makes RDPDR channel blocks
  - Then do spraying same as RDPSND channel
  - The server send timeout is 20 seconds (disconnect after timeout)

### Nonpaged pool spraying with REFRESH_RECT pdu
- A server (```RDPWD!WDW_InvalidateRect```) dispatch REFRESH_RECT command to Command (internal) channel
  - Allocate size is 2056+channel_buffer_struct_size
    - If no big hole, each allocation will be at start of page
  - But can control only 8 bytes
- If target is single processor (such as VM) and big data is sent to a RDPDR channel very fast, you might see the target keep allocating nonpaged pool memory. That becauses a server CPU is busy receiving data and creating channel buffer (no time to process data).
- The Command channel is created before "Connection Finalization" phase of RDP connection sequeunce
  - Without last step of "Connection Finalization" phase, server never read data from Command channel
  - RDP handshake timeout is 60 seconds

### MmNonPagedPoolStart address
- MmNonPagedPoolStart is varied depened on PFN Database size.
- Common PFN Database size is 20MB-200MB (but can be >4GB).
- To lessen the issue, large nonpaged pool spraying is needed (e.g. 1GB).
  - So 1 picked address can be used for many targets.
- Can use RDP 4.0 bulk compression to reduce the network data.
  - With compression, I can do nonpaged pool spraying size ~1GB with a few MB network data (less than a few seconds over Wifi).


### Reclaim the freed MS_T120 channel
- MS_T120 channel reader thread has high priority.
- When sending special data to MS_T120 channel for freeing the channel, the channel is freed by the reader thread.
- Normally, the MS_T120 freed channel chunk is put to pool lookaside lists (defined per processor).
  - To reclaim the freed chunk, the allocation must be done on the same logical processor.
  - Lookaside lists are disabled while booting. Have to wait 2 minutes after boot.
- For single processor, the reader thread will preempt the receiver thread.
  - The free channel chunk will be put to pool lookaside list.
  - Then just allocate with the same channel object size to get the freed object chunk.
  - So send only 1 packet to reclaim the freed channel is enough.
- For multiprocessor, the reader thread might run on another idle processor.
  - The MS_T120 free channel chunk will be put to pool lookaside list of its processor.
  - The receiving thread normally is run on different processor.
  - So reclaim the free channel chunk is impossible (if the receiver thread is still not run on same processor as MS_T120 reader thread).
- For increasing reliability of reclaiming the freed MS_T120 channel on multiprocessor target.
  - I create multiple RDP connections for reclaiming the freed MS_T120 channel from many connections.
  - High success rate with good connection (Wifi is considered as good).
  - Has no test over the real internet connection.


### Timeout issue
- Sending mouse move event can refresh the timeout on server


### Multiple MS_T120 channel
- When requesting MS_T120 channel. the virtual channel id value in CHANNEL object is modified
- If MS_T120 is 5th channel. the MS_T120 vc id in CHANNEL object will be modified to 4
- If MS_T120 is 5th and 6th channel. the MS_T120 vc id in CHANNEL object will be modified to 4 then 5
- If MS_T120 is 5th and 31th channel. the MS_T120 vc id in CHANNEL object will be modified to 4 then 31
  - Can detect target architecture on patched target
  - Can disconnect after triggered free without a crash
  - Also can trigger UAF without disconnection

**Note:** Virtual channel id 7 is reserved for CTXTW


### Detect target OS
- Can use "Refresh Rect" command on Windows logo at bottom center of screen
- Then check the response size on fast path


### SSL/TLS
- Maximum TLS record size is 32KB.
- Server must receive whole TLS record before decryption
- This can be used for sending many RDP requests to server at once.
