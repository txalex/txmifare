#include "txhelperslib.h"

#define MF_KEY_A					0x60
#define MF_KEY_B					0x61
#define MF_LEN_KEY					6
#define MF_LEN_ACCESS_BITS			4
#define MF_LEN_BLOCK				16
#define MF_OFFSET_ACCESS_BITS		6
#define MF_OFFSET_KEY_B				10
#define MB_OFFSET_WRITE_DATA		5
#define MF_1K_NUM_BLOCKS_IN_SECTOR	4
#define MF_1K_NUM_SECTORS			16
#define MF_1K_NUM_BLOCKS			64
#define MF_4K_NUM_BLOCKS			256

// # of blocks in a given sector type
#define MF_NUM_DATA_BLOCKS_MANU_SECTOR		2
#define MF_NUM_DATA_BLOCKS_LITTLE_SECTOR	3
#define MF_NUM_DATA_BLOCKS_BIG_SECTOR		15

// # of sectors of a given type
#define MF_4K_NUM_LITTLE_SECTORS	32
#define MF_4K_NUM_BIG_SECTORS		8
#define MF_4K_NUM_SECTORS			40

// # of usab;e blocks
#define MF_1K_NUM_USABLE_BLOCKS	(MF_1K_NUM_BLOCKS - MF_1K_NUM_SECTORS - 1)
#define MF_4K_NUM_USABLE_BLOCKS	(MF_4K_NUM_BLOCKS - MF_4K_NUM_SECTORS - 1)

// # of usable bytes
#define MF_1K_USABLE_BYTES (MF_1K_NUM_USABLE_BLOCKS * 16)
#define MF_4K_USABLE_BYTES (MF_4K_NUM_USABLE_BLOCKS * 16)

const BYTE MF_DEFAULT_ACCESS_BITS[] = {0xFF, 0x07, 0x80, 0x69};
const BYTE MF_DEFAULT_KEY[]			= {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
const BYTE MF_SECTOR_TRAILERS[]		= {3, 7, 11, 15, 19, 23, 27, 31, 35, 39, 43, 47, 51, 55, 59, 63, 67, 71, 75, 79, 83, 87, 91, 95, 99, 103, 107, 111, 115, 119, 123, 127, 143, 159, 175, 191, 207, 223, 239, 255};

#define MF_NUM_KEYS 2
                                    
// card type constants
#define MF_1K	0
#define MF_4K	1
//
////const BYTE MF_SECTOR_TRAILER_BLOCKS[] = {3, 7, 11, 15, 19, 23, 27, 31, 35, 39, 43, 47, 51, 55, 59];
//
//// {block offset, max length}
//const BYTE MF_1K_MAX_LENGTHS[MF_1K_NUM_BLOCKS-1][2] = {{0,0},{1,47},{2,46},{3,0},{4,45},{5,44},{6,43},{7,0},{8,42},{9,41},{10,40},{11,0},
//													   {12,39},{13,38},{14,37},{15,0},{16,36},{17,35},{18,34},{19,0},{20,33},{21,32},{22,31},
//												       {23,0},{24,30},{25,29},{26,28},{27,0},{28,27},{29,26},{30,25},{31,0},{32,24},{33,23},
//													   {34,22},{35,0},{36,21},{37,20},{38,19},{39,0},{40,18},{41,17},{42,16},{43,0},{44,15},
//												       {45,14},{46,13},{47,0},{48,12},{49,11},{50,10},{51,0},{52,9},{53,8},{54,7},{55,0},{56,6},
//												       {57,5},{58,4},{59,0},{60,3},{61,2},{62,1}};

DWORD MfAuth(TX_PCSC_INFO* pstPCSCInfo, BYTE bBlock, BYTE bKeyType);
DWORD MfLoadKey(TX_PCSC_INFO* pstPCSCInfo, BYTE* baKey);
DWORD MfWriteBlock(TX_PCSC_INFO* pstPCSCInfo, BYTE bBlock, BYTE* baData);
DWORD MfReadBlock(TX_PCSC_INFO* pstPCSCInfo, BYTE bBlock, BYTE* baData);
DWORD MfReadWriteCard(TX_PCSC_INFO* pstPCSCInfo, BYTE* baKey, BYTE bKeyType, BYTE* baData, int iOffset, int iLen, bool bRead);

