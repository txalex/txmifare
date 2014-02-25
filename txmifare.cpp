#include "txmifare.h"

DWORD MfAuth(TX_PCSC_INFO* pstPCSCInfo, BYTE bBlock, BYTE bKeyType)
{
	PrintDebugInfo(FILE_LOG, L"MfAuth()");

	DWORD		dwRet = 0,
				dwLen = 0;
	BYTE		baAuth[] = {0xFF, 0x86, 0x00, 0x00, 0x05, 0x01, 0x00, bBlock, bKeyType, 0x00},
				baRecvBuf[255] = {0};

	dwLen = LEN_MAX_RESPONSE;

	// auth the key
	if (SCARD_S_SUCCESS != (dwRet = SCardTransmit(
										pstPCSCInfo->hCard, 
										0, 
										baAuth, 
										sizeof(baAuth), 
										NULL, 
										baRecvBuf, 
										&dwLen)))
	{
		PrintDebugInfo(FILE_LOG, L"MfAuth()::SCardTransmit(CSN) failed: 0x%.2X", dwRet);
	} 
	else if (STATUS_BYTE_SUCCESS != baRecvBuf[dwLen - 2]) // more bytes available
	{
		dwRet = baRecvBuf[dwLen-2] * 0x100 + baRecvBuf[dwLen-1];
		PrintDebugInfo(FILE_LOG, L"MfAuth()::SCardTransmit() failed: 0x%.2X%.2X", baRecvBuf[dwLen-2], baRecvBuf[dwLen-1]);
	}
	else
		PrintDebugInfo(FILE_LOG, L"MfAuth()::SCardTransmit(block %d) success", bBlock);

	return dwRet;
}

DWORD MfLoadKey(TX_PCSC_INFO* pstPCSCInfo, BYTE* baKey)
{
	PrintDebugInfo(FILE_LOG, L"MfLoadKey()");

	DWORD		dwRet = 0,
				dwLen = 0;
	BYTE		baAuth[] = {0xFF, 0x82, 0x20, 0x00, 0x06, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
				baRecvBuf[255] = {0};

	dwLen = LEN_MAX_RESPONSE;

	memcpy(&baAuth[5], baKey, MF_LEN_KEY);

	// load the key
	if (SCARD_S_SUCCESS != (dwRet = SCardTransmit(
										pstPCSCInfo->hCard, 
										0, 
										baAuth, 
										sizeof(baAuth), 
										NULL,
										baRecvBuf, 
										&dwLen))){
		PrintDebugInfo(FILE_LOG, L"MfLoadKey()::SCardTransmit() failed: 0x%.2X", dwRet);
	}
	else if (STATUS_BYTE_SUCCESS != baRecvBuf[dwLen - 2])
	{
		dwRet = baRecvBuf[dwLen-2] * 0x100 + baRecvBuf[dwLen-1];
		PrintDebugInfo(FILE_LOG, L"MfLoadKey()::SCardTransmit() failed: 0x%.2X%.2X", baRecvBuf[dwLen-2], baRecvBuf[dwLen-1]);
	}
	else{
		PrintDebugInfo(FILE_LOG, L"MfLoadKey()::SCardTransmit() success");
	}

	return dwRet;
}


DWORD MfWriteBlock(TX_PCSC_INFO* pstPCSCInfo, BYTE bBlock, BYTE* baData)
{
	PrintDebugInfo(FILE_LOG, L"MfWrite()");

	DWORD		dwRet = 0,
				dwLen = 0;
	BYTE		baWrite[] = {0xFF, 0xD6, 0x00, bBlock, 0x10, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
				baRecvBuf[255] = {0};

	// copy the data to the APDU
	memcpy(&baWrite[MB_OFFSET_WRITE_DATA], baData, MF_LEN_BLOCK);

	dwLen = LEN_MAX_RESPONSE;

	// write the data
	if (SCARD_S_SUCCESS != (dwRet = SCardTransmit(
										pstPCSCInfo->hCard, 
										0, 
										baWrite, 
										sizeof(baWrite), 
										NULL, 
										baRecvBuf, 
										&dwLen)))
	{
		PrintDebugInfo(FILE_LOG, L"MfWrite()::SCardTransmit() failed: 0x%.2X", dwRet);
	} 
	else if (STATUS_BYTE_SUCCESS != baRecvBuf[dwLen - 2]) 
	{ 
		dwRet = baRecvBuf[dwLen-2] * 0x100 + baRecvBuf[dwLen-1];
		PrintDebugInfo(FILE_LOG, L"MfWrite()::SCardTransmit() failed: 0x%.2X%.2X", baRecvBuf[dwLen-2], baRecvBuf[dwLen-1]);
	}
	else
		PrintDebugInfo(FILE_LOG, L"MfWrite()::SCardTransmit(block %d) success", bBlock);

	return dwRet;
}

DWORD MfReadBlock(TX_PCSC_INFO* pstPCSCInfo, BYTE bBlock, BYTE* baData)
{
	PrintDebugInfo(FILE_LOG, L"MfRead()");

	DWORD		dwRet = 0,
				dwLen = 0;
	BYTE		baRead[] = {0xFF, 0xB0, 0x00, bBlock, 0x00},
				baRecvBuf[255] = {0};

	dwLen = 0x12;	// 18...mifare block length + status word length

	// write the data
	if (SCARD_S_SUCCESS != (dwRet = SCardTransmit(
										pstPCSCInfo->hCard, 
										//0, 
										pstPCSCInfo->pioPCI,
										baRead, 
										sizeof(baRead), 
										NULL, 
										baRecvBuf, 
										&dwLen)))
	{
		PrintDebugInfo(FILE_LOG, L"MfRead()::SCardTransmit() failed: 0x%.2X", dwRet);
	} 
	else if (STATUS_BYTE_SUCCESS != baRecvBuf[dwLen - 2]) 
	{
		dwRet = baRecvBuf[dwLen-2] * 0x100 + baRecvBuf[dwLen-1];
		PrintDebugInfo(FILE_LOG, L"MfRead()::SCardTransmit() failed: 0x%.2X%.2X", baRecvBuf[dwLen-2], baRecvBuf[dwLen-1]);
	}
	else
		PrintDebugInfo(FILE_LOG, L"MfRead()::SCardTransmit(block %d) success", bBlock);

	memcpy(baData, baRecvBuf, MF_LEN_BLOCK);

	return dwRet;
}


DWORD MfReadWriteCard(TX_PCSC_INFO* pstPCSCInfo, BYTE* baKey, BYTE bKeyType, BYTE* baData, int iOffset, int iLen, bool bRead)
{
	DWORD		dwRet = 0;
	BYTE		baBlock[16] = {0},
				baRead[752] = {0};	// 752 is the max # of bytes that fit on a Mifare 1k...(3*16*15) + (2*16)
	int			i,
				iBlockNum = 0,
				iBlocksNeeded = 0,
				iBlockCnt = 0;
	bool		bIsSectorTrailer = false,	
				bIsSectorBlockZero = false;

	PrintDebugInfo(FILE_LOG, L"MfReadWriteCard()");

	// if offset is last block
	// need to fix with ATR decoding to determine if 1K or 4K
	//if(iOffset == MF_1K_NUM_BLOCKS - 1)
	//{
	//	PrintDebugInfo(FILE_LOG, L"MfReadWriteCard()::invalid offset");
	//	return ERR_INVALID_OFFSET;
	//}

	// if offset is block 0 or a sector trailer, increase by 1
	//for(i=0; i<MF_1K_NUM_SECTORS; i++)
	for(i=0; i<sizeof(MF_SECTOR_TRAILERS); i++)
	{
		if(iOffset == 0 || iOffset == MF_SECTOR_TRAILERS[i])
		{
			iOffset++;
			break;
		}
	}

	// determine how many block are needed to store all the data
	if(iLen % 16 == 0)
		iBlocksNeeded = iLen / MF_LEN_BLOCK;
	else
		iBlocksNeeded = (iLen / MF_LEN_BLOCK) + 1;

	// if too much data for offset
	//if((iBlocksNeeded > MF_1K_MAX_LENGTHS[iOffset][1]))
	//{
	//	PrintDebugInfo(FILE_LOG, L"MfReadWriteCard()::offset too great for data length");
	//	return ERR_INVALID_OFFSET;
	//}

	try
	{
		// load the key to the reader
		if(SCARD_S_SUCCESS != (dwRet = MfLoadKey(pstPCSCInfo, baKey)))
		{
			PrintDebugInfo(FILE_LOG, L"MfReadWriteCard()::MfLoadKey() failed - 0x%.2X", dwRet);
			throw dwRet;
		}

		iBlockNum = iOffset;

		// authenticate the first block  
		if(SCARD_S_SUCCESS != (dwRet = MfAuth(pstPCSCInfo, iBlockNum, bKeyType)))
		{
			PrintDebugInfo(FILE_LOG, L"MfReadWriteCard()::MfAuth(%d) failed - 0x%.2X", iBlockNum, dwRet);
			throw dwRet;
		}

		do
		{
			bIsSectorTrailer = false;

			// check for sector trailer and block 0
			for(i=0; i<sizeof(MF_SECTOR_TRAILERS); i++)
			{
				if(iBlockNum == MF_SECTOR_TRAILERS[i])
				{
					bIsSectorTrailer = true;
					break;
				}
				else if(iBlockNum == MF_SECTOR_TRAILERS[i] + 1)	// check is f
				{
					bIsSectorBlockZero = true;
					break;
				}
			}

			// if not a sector trailer
			if(!bIsSectorTrailer)
			{
				// reauthenticate if entering a new sector
				if(bIsSectorBlockZero)
				{
					if(SCARD_S_SUCCESS != (dwRet = MfAuth(pstPCSCInfo, iBlockNum, bKeyType)))
					{
						PrintDebugInfo(FILE_LOG, L"MfReadWriteCard()::MfAuth(%d) failed - 0x%.2X", iBlockNum, dwRet);
						throw dwRet;
					}

					bIsSectorBlockZero = false;
				}

				if(bRead == true)	// if reading
				{
					memset(baBlock, 0, sizeof(baBlock));
					
					// read the block
					if(SCARD_S_SUCCESS != (dwRet = MfReadBlock(pstPCSCInfo, iBlockNum, baBlock)))
					{
						PrintDebugInfo(FILE_LOG, L"MfReadWriteCard()::MfRead(block %d) failed - 0x%.2X", iBlockNum, dwRet);
						throw dwRet;
					} 

					// copy just read 16 bytes to big array
					memcpy(&baRead[iBlockCnt*MF_LEN_BLOCK], baBlock, MF_LEN_BLOCK); 
				}
				else	// if writing
				{
					memcpy(baBlock, &baData[iBlockCnt*MF_LEN_BLOCK], sizeof(baBlock));
					
					// write the block
					if(SCARD_S_SUCCESS != (dwRet = MfWriteBlock(pstPCSCInfo, iBlockNum, baBlock)))
					{
						PrintDebugInfo(FILE_LOG, L"MfReadWriteCard()::MfWrite(block %d) failed - 0x%.2X", iBlockNum, dwRet);
						throw dwRet;
					} 
				}

				iBlockCnt++;	// used to track where on the big data set to read/write the next 16 bytes to/from 
			}

			iBlockNum++;		// used to track where on the card the loop is pointing
			
		}
		while(iBlocksNeeded > iBlockCnt);

		// if reading, copy the read data to the return array
		if(bRead == true)
			memcpy(baData, baRead, iLen);

		throw dwRet;
	}
	catch(DWORD dwErr)
	{
		PrintDebugInfo(FILE_LOG, L"MfReadWriteCard()::end");
		//DeactivatePCSC(pstPCSCInfo);
		return dwErr;
	}
}