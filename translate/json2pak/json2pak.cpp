#include <stdint.h>
#include <windows.h>
#include <stdio.h>
#include "..\cJSON\cJSON.h"
#include <vector>

template<typename Function>
bool mapfile(const char *file, Function f)
{
    HANDLE hfile = CreateFileA(file,
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL, NULL);
    if (hfile == INVALID_HANDLE_VALUE)
    {
        return false;
    }
    BY_HANDLE_FILE_INFORMATION file_info;
    GetFileInformationByHandle(hfile, &file_info);
    unsigned long file_size = file_info.nFileSizeLow;
    HANDLE hfilemap = CreateFileMapping(hfile, NULL, PAGE_READONLY, 0, 0, NULL);
    CloseHandle(hfile);
    unsigned char *buf = (unsigned char*)MapViewOfFile(hfilemap, FILE_MAP_READ, 0, 0, 0);
    CloseHandle(hfilemap);

    bool ret = f(buf, file_size);

    UnmapViewOfFile(buf);
    return ret;
}
#pragma pack(push)
#pragma pack(1)

#define PACK_FILE_VERSION  (4)

struct PAK_HEADER
{
    uint32_t version;
    uint32_t num_entries;
    uint8_t encodeing;
};

struct PAK_ENTRY
{
    uint16_t id;
    uint32_t offset;
};
#pragma pack(pop)

int main(int argc, char *argv[])
{
    bool ret = mapfile("locale.json",[&](unsigned char *buffer, unsigned long size){
        cJSON *root = cJSON_Parse((char*)buffer);
        if (!root) return false;

        PAK_HEADER header;
        header.version = PACK_FILE_VERSION;
        header.num_entries = 0;
        header.encodeing = 1;

        std::vector <PAK_ENTRY> entrys;
        std::vector <BYTE> content_buffer;

        cJSON *subitem = root->child;
        while (subitem)
        {
            PAK_ENTRY entry;
            entry.id = atoi(subitem->string);
            entry.offset = content_buffer.size();

            content_buffer.insert(content_buffer.end(), subitem->valuestring, subitem->valuestring + strlen(subitem->valuestring));

            entrys.push_back(entry);
            header.num_entries++;

            subitem = subitem->next;
        }

        PAK_ENTRY entry;
        entry.id = 0;
        entry.offset = content_buffer.size();
        entrys.push_back(entry);
        for (auto &entry : entrys)
        {
            entry.offset += sizeof(PAK_ENTRY) * entrys.size() + sizeof(header);
        }

        FILE *fp = fopen("locale.pak", "wb");
        if (fp)
        {
            fwrite(&header, sizeof(header), 1, fp);
            fwrite(&entrys[0], sizeof(PAK_ENTRY) * entrys.size(), 1, fp);
            fwrite(&content_buffer[0], content_buffer.size(), 1, fp);
            fclose(fp);
        }
        printf("生成locale.pak完成，可修改为你要的名称");
        getchar();
        return true;
    });
    if (!ret)
    {
        printf("未找到locale.json文件");
        getchar();
    }
}
