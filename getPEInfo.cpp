#include <windows.h>
#include <winnt.h>
#include <stdio.h>

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

   UnmapViewOfFile(mappedFileAddress);
   CloseHandle(fileMappingObject);
   CloseHandle(dumpFileDescriptor);
   
   return 0;
}
