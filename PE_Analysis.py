import sys
import collections
def PrintALL(dic):
    print(dic['name']+':\n'+'_'*56)
    n = 0
    for i in dic['data']:
        sys.stdout.write('%02X' % ord(i) + ' ')
        if (n+1)%8 == 0:
            sys.stdout.write('   ')
        if (n+1)%16 == 0:
            sys.stdout.write('\n')
        n += 1
    sys.stdout.write('\n\n')

def Print(dic):
	for key in dic:
		if key == 'DataDirectory':
			PrintALL(dic[key])
		else:
			print(key,dic[key])
	sys.stdout.write('\n')

def Cul(ad):
    n = 1
    ans = 0
    for i in ad:
        ans += n*ord(i)
        n *= 256
    return ans 

print('Input file\'s name')
filename = raw_input()
file = open(filename,'rb')
DATA_STR = file.read()
file.close()

IMAGE_DOS_HEADER = {\
'name':'IMAGE_DOS_HEADER',\
'data':DATA_STR[:64]}

e_lfanew = Cul(IMAGE_DOS_HEADER['data'][-4:])

DOS_Stub = {\
'name':'DOS Stub',\
'data':DATA_STR[65:e_lfanew-1]}

IMAGE_FILE_HEADER = collections.OrderedDict()
IMAGE_FILE_HEADER['Machine']=hex(Cul(DATA_STR[e_lfanew+4:e_lfanew+6]))
IMAGE_FILE_HEADER['NumberOfSections']=Cul(DATA_STR[e_lfanew+6:e_lfanew+8])
IMAGE_FILE_HEADER['TimeDateStamp']=Cul(DATA_STR[e_lfanew+8:e_lfanew+12])
IMAGE_FILE_HEADER['PointerToSymbolTable']=hex(Cul(DATA_STR[e_lfanew+12:e_lfanew+16]))
IMAGE_FILE_HEADER['NumberOfSymbols']=Cul(DATA_STR[e_lfanew+16:e_lfanew+20])
IMAGE_FILE_HEADER['SizeOfOptionalHeader']=Cul(DATA_STR[e_lfanew+20:e_lfanew+22])
IMAGE_FILE_HEADER['Characteristics']=Cul(DATA_STR[e_lfanew+22:e_lfanew+24])

ADRESS = e_lfanew + 24
IMAGE_OPTIONAL_HEADER = collections.OrderedDict()
IMAGE_OPTIONAL_HEADER['Magic']=hex(Cul(DATA_STR[ADRESS:ADRESS+2]))
IMAGE_OPTIONAL_HEADER['MajorLinkerVersion']=Cul(DATA_STR[ADRESS+2:ADRESS+3])
IMAGE_OPTIONAL_HEADER['MinorLinkerVersion']=Cul(DATA_STR[ADRESS+3:ADRESS+4])
IMAGE_OPTIONAL_HEADER['SizeOfCode']=Cul(DATA_STR[ADRESS+4:ADRESS+8])
IMAGE_OPTIONAL_HEADER['SizeOfInitializedData']=Cul(DATA_STR[ADRESS+8:ADRESS+12])
IMAGE_OPTIONAL_HEADER['SizeOfUninitializedData']=Cul(DATA_STR[ADRESS+12:ADRESS+16])
IMAGE_OPTIONAL_HEADER['AddressOfEntryPoint']=hex(Cul(DATA_STR[ADRESS+16:ADRESS+20]))
IMAGE_OPTIONAL_HEADER['BaseOfCode']=Cul(DATA_STR[ADRESS+20:ADRESS+24])
IMAGE_OPTIONAL_HEADER['BaseOfData']=Cul(DATA_STR[ADRESS+24:ADRESS+28])
IMAGE_OPTIONAL_HEADER['ImageBase']=Cul(DATA_STR[ADRESS+28:ADRESS+32])
IMAGE_OPTIONAL_HEADER['SectionAlignment']=Cul(DATA_STR[ADRESS+32:ADRESS+36])
IMAGE_OPTIONAL_HEADER['FileAlignment']=Cul(DATA_STR[ADRESS+36:ADRESS+40])
IMAGE_OPTIONAL_HEADER['MajorOperatingSystemVersion']=Cul(DATA_STR[ADRESS+40:ADRESS+42])
IMAGE_OPTIONAL_HEADER['MinorOperatingSystemVersion']=Cul(DATA_STR[ADRESS+42:ADRESS+44])
IMAGE_OPTIONAL_HEADER['MajorImageVersion']=Cul(DATA_STR[ADRESS+44:ADRESS+46])
IMAGE_OPTIONAL_HEADER['MinorImageVersion']=Cul(DATA_STR[ADRESS+46:ADRESS+48])
IMAGE_OPTIONAL_HEADER['MajorSubsystemVersion']=Cul(DATA_STR[ADRESS+48:ADRESS+50])
IMAGE_OPTIONAL_HEADER['MinorSubsystemVersion']=Cul(DATA_STR[ADRESS+50:ADRESS+52])
IMAGE_OPTIONAL_HEADER['Win32VersionValue']=Cul(DATA_STR[ADRESS+52:ADRESS+56])
IMAGE_OPTIONAL_HEADER['SizeOfImage']=Cul(DATA_STR[ADRESS+56:ADRESS+60])
IMAGE_OPTIONAL_HEADER['SizeOfHeaders']=Cul(DATA_STR[ADRESS+60:ADRESS+64])
IMAGE_OPTIONAL_HEADER['CheckSum']=Cul(DATA_STR[ADRESS+64:ADRESS+68])
IMAGE_OPTIONAL_HEADER['Subsystem']=Cul(DATA_STR[ADRESS+68:ADRESS+70])
IMAGE_OPTIONAL_HEADER['DllCharacteristics']=Cul(DATA_STR[ADRESS+70:ADRESS+72])
IMAGE_OPTIONAL_HEADER['SizeOfStackReserve']=Cul(DATA_STR[ADRESS+72:ADRESS+76])
IMAGE_OPTIONAL_HEADER['SizeOfStackCommit']=Cul(DATA_STR[ADRESS+76:ADRESS+80])
IMAGE_OPTIONAL_HEADER['SizeOfHeapReserve']=Cul(DATA_STR[ADRESS+80:ADRESS+84])
IMAGE_OPTIONAL_HEADER['SizeOfHeapCommit']=Cul(DATA_STR[ADRESS+84:ADRESS+88])
IMAGE_OPTIONAL_HEADER['LoaderFlags']=Cul(DATA_STR[ADRESS+88:ADRESS+92])
IMAGE_OPTIONAL_HEADER['NumberOfRvaAndSizes']=Cul(DATA_STR[ADRESS+92:ADRESS+96])
IMAGE_OPTIONAL_HEADER['DataDirectory']={'name':'DataDirectory','data':DATA_STR[ADRESS+96:ADRESS+224]}

Signature = 'Signture: '+DATA_STR[e_lfanew:e_lfanew+4]
IMAGE_NT_HEADER = [Signature,IMAGE_FILE_HEADER,IMAGE_OPTIONAL_HEADER]

ADRESS = e_lfanew+248
IMAGE_SECTION_HEADER = []
SECTIONS = []
for i in range(IMAGE_FILE_HEADER['NumberOfSections']):
	temp = collections.OrderedDict()
	temp['Name']=DATA_STR[ADRESS:ADRESS+8]
	temp['PhysicalAddress/VirtualSize']=hex(Cul(DATA_STR[ADRESS+8:ADRESS+12]))
	temp['VirtualAddress']=hex(Cul(DATA_STR[ADRESS+12:ADRESS+16]))
	temp['SizeOfRawData']=Cul(DATA_STR[ADRESS+16:ADRESS+20])
	temp['PointerToRawData']=hex(Cul(DATA_STR[ADRESS+20:ADRESS+24]))
	temp['PointerToRelocations']=hex(Cul(DATA_STR[ADRESS+24:ADRESS+28]))
	temp['PointerToLinenumbers']=hex(Cul(DATA_STR[ADRESS+28:ADRESS+32]))
	temp['NumberOfRelocations']=Cul(DATA_STR[ADRESS+32:ADRESS+34])
	temp['NumberOfLinenumbers']=Cul(DATA_STR[ADRESS+34:ADRESS+36])
	temp['Characteristics']=hex(Cul(DATA_STR[ADRESS+36:ADRESS+40]))
	IMAGE_SECTION_HEADER.append(temp)
	ADRESS+=40
	exec('a' + '%d'%i + '= {\'name\':temp[\'Name\'],\
\'data\':DATA_STR[int(temp[\'PointerToRawData\'],16):\
int(temp[\'PointerToRawData\'],16)+temp[\'SizeOfRawData\']]}')
	SECTIONS.append(eval('a' + '%d'%i))
PrintALL(IMAGE_DOS_HEADER)
PrintALL(DOS_Stub)
print('IMAGE_NT_HEADER'+':\n'+'_'*56)
print(IMAGE_NT_HEADER[0])
print('	IMAGE_FILE_HEADER'+':\n'+'_'*56)
Print(IMAGE_NT_HEADER[1])
print('	IMAGE_OPTIONAL_HEADER'+':\n'+'_'*56)
Print(IMAGE_NT_HEADER[2])
print('IMAGE_SECTION_HEADER'+':\n'+'_'*56)
for i in range(i+1):
	Print(IMAGE_SECTION_HEADER[i])
print('SECTIONS'+':\n'+'_'*56)
for i in range(i+1):
	PrintALL(SECTIONS[i])