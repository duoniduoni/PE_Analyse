#include <windows.h>
#include <winnt.h>
#include <stdio.h>

DWORD RVAToOffset(DWORD rav, PIMAGE_SECTION_HEADER pSectionHeader, int numOfSection)
{
   for(int i = 0; i < numOfSection; i++)
   {
      if(
            pSectionHeader[i].VirtualAddress <= rav &&
            pSectionHeader[i].VirtualAddress + pSectionHeader[i].SizeOfRawData > rav
        )
      {
         return pSectionHeader[i].PointerToRawData + rav - 
            pSectionHeader[i].VirtualAddress;
      }
   }

   return -1;
}

void showExportTable(PIMAGE_DATA_DIRECTORY pExportTable,
      PIMAGE_SECTION_HEADER pSectionHeader, int numOfSection,
      void * pMappedAddress)
{
   DWORD fileOffset = RVAToOffset(pExportTable->VirtualAddress, pSectionHeader, numOfSection);
   PIMAGE_EXPORT_DIRECTORY pExportDirectory = (PIMAGE_EXPORT_DIRECTORY )((char *)pMappedAddress + fileOffset); 

   fileOffset = RVAToOffset(pExportDirectory->Name, pSectionHeader, numOfSection);
   char * strDllName = (char *)pMappedAddress + fileOffset;
   fileOffset = RVAToOffset(pExportDirectory->AddressOfNames, pSectionHeader, numOfSection);
   DWORD *dNames= (DWORD*)((char *)pMappedAddress + fileOffset);

   printf("\t\tExport Info :\n"
         "\t\t\tName [%s]\n"
         "\t\t\tBase [%d]\n"
         "\t\t\tNumberOfFunctions [%d]\n"
         "\t\t\tNumberOfNames [%d]\n"
         "\t\t\tAddressOfNames [%p]\n",
         strDllName, 
         pExportDirectory->Base, 
         pExportDirectory->NumberOfFunctions, 
         pExportDirectory->NumberOfNames,
         dNames[0]);

   printf("\t\tnames :\n");
   for(int i = 0; i < pExportDirectory->NumberOfNames; i++)
   {
      fileOffset = RVAToOffset(dNames[i], pSectionHeader, numOfSection);
      printf("\t\t\t%s\n", (char *)pMappedAddress + fileOffset);
   }
}

void showImportTable(PIMAGE_DATA_DIRECTORY pImportTable, 
      PIMAGE_SECTION_HEADER pSectionHeader, int numOfSection,
      void * pMappedAddress)
{
   DWORD fileOffset = RVAToOffset(pImportTable->VirtualAddress, pSectionHeader, numOfSection);
   if((int)fileOffset < 0)
   {
      printf("show import fail, rav to offset fail !\n");
      return ;
   }

   PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((char *)pMappedAddress + fileOffset); 
   int numOfImportDescriptor = pImportTable->Size / sizeof(IMAGE_IMPORT_DESCRIPTOR);

   printf("Import Table Details : \n");

   for(int i = 0; i < numOfImportDescriptor; i++)
   {
      if(pImportDescriptor[i].Name == 0)
         break;

      fileOffset = RVAToOffset(pImportDescriptor[i].Name, pSectionHeader, numOfSection);
      printf("\timport Dll name [%s]\n", (char *)pMappedAddress + fileOffset);

      //解析桥1
      fileOffset = RVAToOffset(pImportDescriptor[i].OriginalFirstThunk, pSectionHeader, numOfSection);
      PIMAGE_THUNK_DATA pThunkData = (PIMAGE_THUNK_DATA)((char *)pMappedAddress + fileOffset); 
      printf("\t\tfirst bridge [%p]:\n", pThunkData);
      for(int j = 0; ; j++)
      {
         if(pThunkData[j].u1.Ordinal == 0)
            break;

         if(IMAGE_SNAP_BY_ORDINAL(pThunkData[j].u1.Ordinal))
         {
            printf("\t\t this thunk data high word is 1, do not know how to dispose !\n");
            continue;
         }

         fileOffset = RVAToOffset(pThunkData[j].u1.Ordinal, pSectionHeader, numOfSection);
         PIMAGE_IMPORT_BY_NAME pImportByName = (PIMAGE_IMPORT_BY_NAME)((char *)pMappedAddress + fileOffset); 
         printf("\t\t%p %s\n", pImportByName->Hint, pImportByName->Name);
      }

      //解析桥2
      fileOffset = RVAToOffset(pImportDescriptor[i].FirstThunk, pSectionHeader, numOfSection);
      pThunkData = (PIMAGE_THUNK_DATA)((char *)pMappedAddress + fileOffset); 
      printf("\n\t\tsecond bridge [%p]:\n", pThunkData);
      for(j = 0; ; j++)
      {
         if(pThunkData[j].u1.Ordinal == 0)
            break;

         if(IMAGE_SNAP_BY_ORDINAL(pThunkData[j].u1.Ordinal))
         {
            printf("\t\t this thunk data high word is 1, do not know how to dispose !\n");
            continue;
         }

         fileOffset = RVAToOffset(pThunkData[j].u1.Ordinal, pSectionHeader, numOfSection);
         PIMAGE_IMPORT_BY_NAME pImportByName = (PIMAGE_IMPORT_BY_NAME)((char *)pMappedAddress + fileOffset); 
         printf("\t\t%p %s\n", pImportByName->Hint, pImportByName->Name);
      }     
   }
}

int main(int argc, char * argv[])
{
   if(argc != 2)
   {
      printf("usage getPEInfo targetName\n");
      return 0;
   }

   HANDLE dumpFileDescriptor = CreateFileA(argv[1], 
         GENERIC_READ | GENERIC_WRITE, 
         FILE_SHARE_READ | FILE_SHARE_WRITE, 
         NULL, 
         OPEN_EXISTING, 
         FILE_ATTRIBUTE_NORMAL, 
         NULL); 
   if(dumpFileDescriptor == NULL)
   {
      printf("CreateFileA Fail \n");
      return 0;
   }

   DWORD fileSize = GetFileSize(dumpFileDescriptor, 0);

   HANDLE fileMappingObject = CreateFileMapping(dumpFileDescriptor,
         NULL,
         PAGE_READWRITE,
         0,
         0,
         NULL);
   if(fileMappingObject == NULL)
   {
      CloseHandle(dumpFileDescriptor);

      printf("CreateFileMapping Fail \n");
      return 0;
   }

   void* mappedFileAddress = MapViewOfFile(fileMappingObject,
         FILE_MAP_ALL_ACCESS,
         0,
         0,
         0);
   if(mappedFileAddress == NULL)
   {
      CloseHandle(dumpFileDescriptor);
      CloseHandle(fileMappingObject);

      printf("MapViewOfFile == NULL \n");
      return 0;
   }

   printf("map file [%s] success, mapped address [%p], file size [%d]\n", argv[1], mappedFileAddress, fileSize);

   do{
      //begin anlayse PE
      if(fileSize <= sizeof(IMAGE_DOS_HEADER))
      {
         printf("file[%s] size too small !\n", argv[1]);
         break;
      }

      PIMAGE_DOS_HEADER pdh = (PIMAGE_DOS_HEADER)mappedFileAddress;
      if(pdh->e_magic != IMAGE_DOS_SIGNATURE)
      {
         printf("file[%s] size dos header e_maigc do not match !\n", argv[1]);
         break;
      }
      printf("file [%s] dos headers check!\n", argv[1]);

      PIMAGE_NT_HEADERS32 pNtHeader = (PIMAGE_NT_HEADERS32)((char *)mappedFileAddress + pdh->e_lfanew);

      if(pNtHeader->Signature != IMAGE_NT_SIGNATURE)
      {
         printf("file[%s] size dos header e_maigc do not match !\n", argv[1]);
         break;
      }
      printf("file [%s] NT headers check!\n", argv[1]);

      printf("\tNumberOfSections [%d]\n"
            "\tSizeOfOptionalHeader [%d]\n",
            pNtHeader->FileHeader.NumberOfSections,
            pNtHeader->FileHeader.SizeOfOptionalHeader);
      int sizeOfOptionalHeader = pNtHeader->FileHeader.SizeOfOptionalHeader;
      if(sizeOfOptionalHeader != IMAGE_SIZEOF_NT_OPTIONAL32_HEADER)
      {
         printf("file[%s] size of optinal header [%d], not match IMAGE_SIZEOF__NT_OPTIONAL32_HEADER!\n", argv[1]);
         break;
      }
      printf("file [%s] NT Optinal Header size check!\n", argv[1]);

      char strDataDirectory[16][32] = {
         "Export Table",
         "Import Table",
         "Resouce Table",
         "Exception Table",
         "Certificate Table",
         "Base Relocation Table",
         "Debuging Information",
         "Architecture-specific data",
         "Global Pointer Register",
         "TLS Table",
         "Load Configuration Table",
         "Bound Import Table",
         "IAT",
         "Delay Import Descripor",
         "CLR",
         "Reserved"
      };
      printf("file [%s] Data Directory :\n", argv[1]);
      PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeader);
      for(int i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; i++)
      {
         PIMAGE_DATA_DIRECTORY pdd = &pNtHeader->OptionalHeader.DataDirectory[i];
         printf("\t[%s -- %p:%d]\n", strDataDirectory[i], 
               pdd->VirtualAddress, pdd->Size);

         switch(i)
         {
            case 0:
               if(pdd->VirtualAddress)
               {
                  showExportTable(&pNtHeader->OptionalHeader.DataDirectory[0],
                        pSectionHeader, pNtHeader->FileHeader.NumberOfSections,
                        mappedFileAddress);
               }
               else
               {
                  printf("\t\t\tdo not have Export Table\n");
               }
               break;

            case 1:
               if(pdd->VirtualAddress)
               {/*
                   showImportTable(&pNtHeader->OptionalHeader.DataDirectory[1],
                   pSectionHeader, pNtHeader->FileHeader.NumberOfSections,
                   mappedFileAddress);*/
               }
               else
               {
                  printf("\t\t\tdo not have Import Table\n");
               }
               break;

            default:
               break;
         }

      }
      printf("file [%s] Section :\n", argv[1]);
      for(i = 0; i < pNtHeader->FileHeader.NumberOfSections; i++)
      {
         printf("\t%d %s [%p - %d - %p]\n", i, 
               pSectionHeader[i].Name,
               pSectionHeader[i].VirtualAddress,
               pSectionHeader[i].SizeOfRawData,
               pSectionHeader[i].PointerToRawData
               );
      }

   }while(0);
   UnmapViewOfFile(mappedFileAddress);
   CloseHandle(fileMappingObject);
   CloseHandle(dumpFileDescriptor);

   return 0;
}
