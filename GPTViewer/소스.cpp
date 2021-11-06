#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>                                                                                 
#include <windows.h>
#include <math.h>
#include <stddef.h>
#include <stdint.h>


typedef unsigned char U8;
typedef unsigned short U16;
typedef unsigned int U32;
typedef unsigned long long int U64;


// 섹터내 파티션 테이블 번지                                                                       
#define PARTITION_TBL_POS	0x1BE

// Primary GPT Header의 인덱스(LBA)
#define GPT_HEADER_LBA 0x1

// 확장 파티션 타입                                                                                
#define PARTITION_TYPE_EXT	0x0F                                                                   

// 섹터 하나의 크기(바이트)
#define SECTOR_SIZE 512

typedef struct _PARTITION
{
    U8 active;		// 부팅 가능 플래그 (0x80 : 부팅 가능, 0x00 : 부팅 불가)                           
    U8 begin[3];	// CHS 모드의 파티션 첫번째 섹터                                                   
    U8 type;		// 파티션 타입                                                                       
    U8 end[3];		// CHS 모드의 파티션 마지막 섹터                                                   
    U32 start;		// LBA 모드의 파티션 위치                                                          
    U32 length;		// 파티션에서 사용되는 섹터의 개수                                                 
} PARTITION, * PPARTITION;

typedef struct _GPT_HEADER
{
    U64 signature; // "EFI PART" signature
    U32 revision; // Version 1.0
    U32 header_size; // size of header, generally 0x5c(92 in decimal) byte
    U32 header_crc32; // crc32 of header
    U32 reserved; // reserved, not used actually
    U64 header_lba; // LBA of gpt header, always 0x01
    U64 header_backup_lba; // LBA of backup gpt header
    U64 partition_start; // starting LBA for partitions, (primary partition table last LBA)+1
    U64 partition_end; // ending LBA for partitions
    U8 guid[16]; // disk guid
    U64 entry_start; // starting LBA address of partition entry tables
    U32 entry_max_num; // maximum number of supported partition entries, generally 0x80(128 in dec)
    U32 entry_size; // size of partiion table entry, generally 128
    U32 table_crc32; // crc32 of partition table
    U8 reserved2[420]; // reserved bytes, not used actually
} GPT_HEADER, * PGPT_HEADER;

typedef struct _GPARTITION
{
    U8 partition_type_guid[16]; // Partition type GUID, can extract informations about file system and OS
    U8 partition_guid[16]; //each partition has unique guid
    U64 start_lba;
    U64 end_lba;
    U64 flags; //attribute flags
    U8 filesystem_name[72]; //name of filesystem, utf-16(le)
} GPARTITION, * PGPARTITION;

typedef struct _MYGUID
{
    U32 segment1;
    U16 segment2;
    U16 segment3;
    U8 segment4[8];
} MYGUID, * PMYGUID;



U32	ExtPartionBase;
U32 drvNumber=0; // driver number to inspect


// drv번 물리 저장소에서 SecAddr번 LBA에서 blocks의 크기만큼 가져와서 buf에 저장한다.
U32  HDD_read(U8 drv, U32 SecAddr, U32 blocks, U8* buf);

// drv번 물리 장치에 SecAddr번 LBA에 blocks의 크기만큼 buf의 데이터를 저장한다.
U32  HDD_write(U8 drv, U32 SecAddr, U32 blocks, U8* buf);

// 디스크 내의 모든 파티션 검색                                                                    
U32		GetLocalPartition(U8 Drv, PPARTITION pPartition);
// 확장 파티션 검색 (재귀 호출)                                                                    
void	SearchExtPartition(U8 drv, PPARTITION pPartition, U32* pnPartitionCnt, int BaseAddr);
// 디스크 내의 부트레코드에서 파티션 테이블 저장                                                   
void	GetPartitionTbl(U8 Drv, U32 nSecPos, PPARTITION pPartition, int nReadCnt);
// 파티션 테이블의 속성 출력                                                                       
void	PrintPartitionInfo(PPARTITION pPartition, U32 nIdx);

// GPT 헤더 가져오기, pGPTHeader가 가리키는 위치에 가져온 데이터를 저장
void GetGPTHeader(U8 Drv, U32 nSecPos, PGPT_HEADER pGPTHeader);

// 디스크 내의 모든 GPT 파티션 가져오기
U32     GetGPTPartitions(U8 Drv, U32 nSecPos, PGPARTITION pGPartition);

// GPT 헤더의 정보 출력
void    PrintGPTHeaderInfo(PGPT_HEADER pGPTHeader, U32 nIdx);

// GPT 파티션의 정보(엔트리) 출력
void PrintGPartitionInfo(PGPARTITION pGPartition, U32 nIdx);

// addr부터 len의 크기만큼 hexdump 출력
void HexDump(U8* addr, U32 len);

// U64형 정수를 2진법으로 출력
void PrintBinary(U64 dec);

// crc32 함수
uint32_t crc32(const char* s, size_t n);


U32 main(void)
{
    GPT_HEADER GPTHeader; // variable to save information of primary gpt header
    GPT_HEADER BackupGPTHeader; // variable to save information of secondary gpt header 

    // get driver number from user (stdin)
    printf("Please enter the disk number to inspect : ");
    scanf("%d", &drvNumber);
    getchar();

    // get and print information of primary gpt header
    GetGPTHeader(drvNumber, 1, &GPTHeader);
    fprintf(stdout, "[Primary GPT Header HexDump]\n");
    HexDump((U8 *)&GPTHeader, sizeof(GPT_HEADER));
    fprintf(stdout, "\n\n\n");
    PrintGPTHeaderInfo(&GPTHeader, 1);
    fprintf(stdout, "\n\n\n");

    // get and print information of partitions (according to primary partition entries)
    GPARTITION Partitions[128];
    memset(Partitions, 0x00, sizeof(Partitions));
    int cntPartitions;
    cntPartitions=GetGPTPartitions(drvNumber, 1, Partitions);
    for (int i = 0; i < cntPartitions; i++)
    {
        PrintGPartitionInfo(&Partitions[i], i+1);
        printf("\n\n\n");
    }

    // get and print information of secondary(backup) gpt header
    GetGPTHeader(drvNumber, GPTHeader.header_backup_lba, &BackupGPTHeader);
    fprintf(stdout, "[Seconary(backup) GPT Header HexDump]\n");
    HexDump((U8*)&BackupGPTHeader, sizeof(GPT_HEADER));
    fprintf(stdout, "\n\n\n");
    PrintGPTHeaderInfo(&BackupGPTHeader, 2);
    fprintf(stdout, "\n\n\n");

    // get and print information of partitions (according to secondary partition entries)
    GPARTITION Partitions2[128];
    memset(Partitions2, 0x00, sizeof(Partitions2));
    int cntPartitions2;
    cntPartitions2 = GetGPTPartitions(drvNumber, GPTHeader.header_backup_lba, Partitions2);
    for (int i = 0; i < cntPartitions2; i++)
    {
        PrintGPartitionInfo(&Partitions2[i], i+1);
        printf("\n\n\n");
    }

    getchar();
}

void PrintBinary(U64 dec)
{
    for (U64 i = (U64)9223372036854775808; i>0; i/=2)
        printf("%d", dec & i ? 1 : 0);
    printf("\n");
    return;
}

void GetGPTHeader(U8 Drv, U32 nSecPos, PGPT_HEADER pGPTHeader)
{
    U8 pSecBuf[512];

    // 물리적 디스크 Drv의 nSecPos번 섹터에서 1개의 블럭을 읽어온다.                                 
    if (HDD_read(Drv, nSecPos, 1, pSecBuf) == 0) {
        printf("Primary GPT Header read failed \n");
        return;
    }

    memcpy(pGPTHeader, pSecBuf, sizeof(GPT_HEADER));
}


U32 GetGPTPartitions(U8 Drv, U32 nSecPos, PGPARTITION pGPartition)
{
    GPT_HEADER GPTHeader;
    GPARTITION GPTPartition;
    U8 buffer[SECTOR_SIZE];
    U32 max_entries;
    U32 entry_start; // starting address(lba) of entries
    U32 entry_count=0; // number of entries
    U32 entry_size;

    GetGPTHeader(Drv, nSecPos, &GPTHeader);
    max_entries = GPTHeader.entry_max_num;
    entry_start = GPTHeader.entry_start;
    entry_size = GPTHeader.entry_size;
    for (int i = 0; i < ceil((float)max_entries/(SECTOR_SIZE/entry_size)); i++)
    {
        HDD_read(Drv, entry_start + i, 1, buffer);
        for (int j = 0; j<(SECTOR_SIZE / entry_size); j++)
        {
            if (((PGPARTITION) & (buffer[entry_size * j]))->end_lba != 0)
            {
                entry_count++;
                memcpy(pGPartition, &buffer[entry_size * j], sizeof(GPARTITION));
                pGPartition++;
            }
            else
                goto EXIT_FOR2;
        }
    }
    EXIT_FOR2:
    return entry_count;
}

void PrintPartitionAttribute(U64 flags)
{
    if ((flags & 1) != 0)
        printf("System Partition\n");
    if ((flags & 2) != 0)
        printf("EFI Firmware\n");
    if ((flags & 4) != 0)
        printf("Legacy BIOS bootable\n");
    if ((((U64)flags >> 60) & 1) == 1)
        printf("Read Only\n");
    if ((((U64)flags >> 61) & 1) == 1)
        printf("Shadow Copy\n");
    if ((((U64)flags >> 62) & 1) == 1)
        printf("Hidden\n");
    if ((((U64)flags >> 63) & 1) == 1)
        printf("No Drive Letter\n");
}

void PrintGUID(U8 guid[16])
{
    printf("%08X", ((PMYGUID)guid)->segment1);
    printf("-%04X", ((PMYGUID)guid)->segment2);
    printf("-%04X-", ((PMYGUID)guid)->segment3);
    for (int i = 0; i < 2; i++)
        printf("%02X", ((PMYGUID)guid)->segment4[i]);
    printf("-");
    for (int i = 2; i < 8; i++)
        printf("%02X", ((PMYGUID)guid)->segment4[i]);
    printf("\n");
}


U32 GetLocalPartition(U8 Drv, PPARTITION pPartition)
{
    U32 i;
    U32 nPartitionCnt = 0;
    PPARTITION pPriExtPartition = NULL;

    // 주 파티션이므로 4개의 파티션 읽어옴                                                           
    GetPartitionTbl(Drv, 0, pPartition, 4);
    for (i = 0; i < 4 && pPartition->length != 0; i++) {
        if (pPartition->type == PARTITION_TYPE_EXT) {
            pPriExtPartition = pPartition;
        }
        pPartition++;		// 다음 파티션으로 이동                                                        
        nPartitionCnt++;	// 파티션 카운트 UP                                                          
    }

    if (!pPriExtPartition)
        return nPartitionCnt;

    //확장 파티션을 검색 할때 사용한다                                                               
    ExtPartionBase = pPriExtPartition->start;

    SearchExtPartition(Drv, pPriExtPartition, &nPartitionCnt, 0);
    return nPartitionCnt;
}

void GetPartitionTbl(U8 Drv, U32 nSecPos, PPARTITION pPartition, int nReadCnt)
{
    U8 pSecBuf[512];

    // 물리적 디스크 Drv의 nSecPos번 섹터에서 1개의 블럭을 읽어온다.                                 
    if (HDD_read(Drv, nSecPos, 1, pSecBuf) == 0) {
        printf("Boot Sector Read Failed \n");
        return;
    }

    memcpy(pPartition, (pSecBuf + PARTITION_TBL_POS), sizeof(PARTITION) * nReadCnt);
}

void SearchExtPartition(U8 drv, PPARTITION pPartition, U32* pnPartitionCnt, int BaseAddr)
{
    int nExtStart = pPartition->start + BaseAddr;
    static int nCnt = 0;

    //데이터를 읽어오기 위해 포인터를 다음 파티션 번지로 이동                                        
    pPartition++;
    //부 파티션과 확장 파티션이 있을 수 있으므로 2개의 파티션을 읽어옴                               
    GetPartitionTbl(drv, nExtStart, pPartition, 2);
    while (pPartition->length != 0 && nCnt == 0)
    {
        (*pnPartitionCnt)++;
        if (pPartition->type == PARTITION_TYPE_EXT)
        {
            SearchExtPartition(drv, pPartition, pnPartitionCnt, ExtPartionBase);
        }
        else {
            pPartition++;
        }

        if (pPartition->length == 0)
            nCnt = 1;
    }
}

void PrintGPTHeaderInfo(PGPT_HEADER pGPTHeader, U32 nIdx)
{
    fprintf(stdout, "[#%u GPT Header Information]\n", nIdx);

    fprintf(stdout, "Signature :\n");
    HexDump((U8*)&(pGPTHeader->signature), sizeof(pGPTHeader->signature));

    fprintf(stdout, "\nRevision :\n");
    HexDump((U8*)&(pGPTHeader->revision), sizeof(pGPTHeader->revision));

    fprintf(stdout, "\nHeader Size : 0x%X (%lu)\n", pGPTHeader->header_size, pGPTHeader->header_size);

    fprintf(stdout, "\nCRC32 of Header : 0x%X (%lu)\n", pGPTHeader->header_crc32, pGPTHeader->header_crc32);
    U32 calculated_crc32;
    GPT_HEADER tmpGPTHeader;
    memcpy(&tmpGPTHeader, pGPTHeader, sizeof(tmpGPTHeader));
    tmpGPTHeader.header_crc32 = 0x0;
    calculated_crc32 = crc32((const char*)&tmpGPTHeader, pGPTHeader->header_size);
    fprintf(stdout, "Calculated CRC32 : 0x%X (%lu)\n", calculated_crc32, calculated_crc32);

    fprintf(stdout, "\nReserved1 : \n");
    HexDump((U8*)&(pGPTHeader->reserved), sizeof(pGPTHeader->reserved));

    fprintf(stdout, "\nLBA of GPT Header : 0x%llX (%llu)\n", pGPTHeader->header_lba, pGPTHeader->header_lba);

    fprintf(stdout, "\nLBA of Backup GPT Header : 0x%llX (%llu)\n", pGPTHeader->header_backup_lba, pGPTHeader->header_backup_lba);

    fprintf(stdout, "\nStarting LBA for Partitions : 0x%llX (%llu)\n", pGPTHeader->partition_start, pGPTHeader->partition_start);

    fprintf(stdout, "\nEnding LBA for Partitions : 0x%llX (%llu)\n", pGPTHeader->partition_end, pGPTHeader->partition_end);

    fprintf(stdout, "\nDisk GUID : \n");
    PrintGUID(pGPTHeader->guid);
    HexDump((U8*)&(pGPTHeader->guid), sizeof(pGPTHeader->guid));

    fprintf(stdout, "\nPartition Table Entry Starting LBA : 0x%llX (%llu)\n", pGPTHeader->entry_start, pGPTHeader->entry_start);

    fprintf(stdout, "\nNumber of Partition Entries : 0x%X (%u)\n", pGPTHeader->entry_max_num, pGPTHeader->entry_max_num);

    fprintf(stdout, "\nSize of Partition Table Entry : 0x%X (%lu)\n", pGPTHeader->entry_size, pGPTHeader->entry_size);

    fprintf(stdout, "\nCRC32 of Partition Table : 0x%X (%lu)\n", pGPTHeader->table_crc32, pGPTHeader->table_crc32);

    fprintf(stdout, "\nReserved2 : \n");
    HexDump((U8*)&(pGPTHeader->reserved2), sizeof(pGPTHeader->reserved2));
}

void PrintGPartitionInfo(PGPARTITION pGPartition, U32 nIdx)
{
    fprintf(stdout, "[PARTITION #%d]\n", nIdx); // partition number

    fprintf(stdout, "Partition Type GUID : \n");
    PrintGUID(pGPartition->partition_type_guid);
    HexDump((U8*)pGPartition->partition_type_guid, sizeof(pGPartition->partition_type_guid));

    fprintf(stdout, "\nUnique Partition GUID : \n");
    PrintGUID(pGPartition->partition_guid);
    HexDump((U8*)pGPartition->partition_guid, sizeof(pGPartition->partition_guid));

    fprintf(stdout, "\nFirst LBA : 0x%llX (%llu)\n", pGPartition->start_lba, pGPartition->start_lba);

    fprintf(stdout, "\nLast LBA : 0x%llX (%llu)\n", pGPartition->end_lba, pGPartition->end_lba);

    fprintf(stdout, "\nAttribute Flags : 0x%llX (%llu)\n", pGPartition->flags, pGPartition->flags);
    PrintBinary(pGPartition->flags);
    PrintPartitionAttribute(pGPartition->flags);

    fprintf(stdout, "\nPartition Name :\n");
    HexDump((U8*)pGPartition->filesystem_name, sizeof(pGPartition->filesystem_name));
}

void PrintPartitionInfo(PPARTITION pPartition, U32 nIdx)
{
    fprintf(stdout, "[PARTITION #%d]\n", nIdx);
    fprintf(stdout, "Bootable : 0x%X\n", pPartition->active);
    fprintf(stdout, "    Type : 0x%X\n", pPartition->type);
    fprintf(stdout, "   Start : %d\n", pPartition->start);
    fprintf(stdout, "  Length : %d\n", pPartition->length);
    fprintf(stdout, "Partition Size : %d MB\n", pPartition->length / 1024 * 512 / 1024);
    fprintf(stdout, "------------------------\n\n");
}

U32  HDD_read(U8 drv, U32 SecAddr, U32 blocks, U8* buf) {
    U32 ret;
    U32 ldistanceLow, ldistanceHigh, dwpointer, bytestoread, numread;

    char cur_drv[100];
    HANDLE g_hDevice;

    sprintf(cur_drv, "\\\\.\\PhysicalDrive%d", (U32)drv);
    g_hDevice = CreateFile(cur_drv, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);

    if (g_hDevice == INVALID_HANDLE_VALUE)	return 0;

    ldistanceLow = SecAddr << 9;
    ldistanceHigh = SecAddr >> (32 - 9);
    dwpointer = SetFilePointer(g_hDevice, ldistanceLow, (long*)&ldistanceHigh, FILE_BEGIN);

    if (dwpointer != 0xFFFFFFFF) {
        bytestoread = blocks * 512;
        ret = ReadFile(g_hDevice, buf, bytestoread, (unsigned long*)&numread, NULL);
        if (ret)	ret = 1;
        else		ret = 0;
    }

    CloseHandle(g_hDevice);
    return ret;
}

U32  HDD_write(U8 drv, U32 SecAddr, U32 blocks, U8* buf) {
    U32 ret = 0;
    U32 ldistanceLow, ldistanceHigh, dwpointer, bytestoread, numread;

    char cur_drv[100];
    HANDLE g_hDevice;

    sprintf(cur_drv, "\\\\.\\PhysicalDrive%d", (U32)drv);
    g_hDevice = CreateFile(cur_drv, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);

    if (g_hDevice == INVALID_HANDLE_VALUE)	return 0;

    ldistanceLow = SecAddr << 9;
    ldistanceHigh = SecAddr >> (32 - 9);
    dwpointer = SetFilePointer(g_hDevice, ldistanceLow, (long*)&ldistanceHigh, FILE_BEGIN);

    if (dwpointer != 0xFFFFFFFF) {
        bytestoread = blocks * 512;
        ret = WriteFile(g_hDevice, buf, bytestoread, (unsigned long*)&numread, NULL);
        if (ret)	ret = 1;
        else    	ret = 0;
    }

    CloseHandle(g_hDevice);
    return ret;
}

void HexDump(U8* addr, U32 len) {
    U8* s = addr, * endPtr = (U8*)((U64)addr + len);
    U32		i, remainder = len % 16;


    // print out 16 byte blocks.
    while (s + 16 <= endPtr) {

        // offset 출력.
        printf("0x%08lx  ", (long)(s - addr));

        // 16 bytes 단위로 내용 출력.
        for (i = 0; i < 16; i++) {
            printf("%02x ", s[i]);
        }
        printf(" ");

        for (i = 0; i < 16; i++) {
            if (s[i] >= 32 && s[i] <= 125)printf("%c", s[i]);
            else printf(".");
        }
        s += 16;
        printf("\n");
    }

    // Print out remainder.
    if (remainder) {

        // offset 출력.
        printf("0x%08lx  ", (long)(s - addr));

        // 16 bytes 단위로 출력하고 남은 것 출력.
        for (i = 0; i < remainder; i++) {
            printf("%02x ", s[i]);
        }
        for (i = 0; i < (16 - remainder); i++) {
            printf("   ");
        }

        printf(" ");
        for (i = 0; i < remainder; i++) {
            if (s[i] >= 32 && s[i] <= 125) printf("%c", s[i]);
            else	printf(".");
        }
        for (i = 0; i < (16 - remainder); i++) {
            printf(" ");
        }
        printf("\n");
    }
    return;
}	// HexDump.

uint32_t crc32(const char* s, size_t n) {
    uint32_t crc = 0xFFFFFFFF;

    for (size_t i = 0; i < n; i++) {
        char ch = s[i];
        for (size_t j = 0; j < 8; j++) {
            uint32_t b = (ch ^ crc) & 1;
            crc >>= 1;
            if (b) crc = crc ^ 0xEDB88320;
            ch >>= 1;
        }
    }

    return ~crc;
}