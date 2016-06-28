#include <stdint.h>
#include <windows.h>
#include <stdio.h>
#include "..\cJSON\cJSON.h"

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
    bool ret = mapfile(argv[1],[&](unsigned char *buffer, unsigned long size){

        PAK_HEADER *pak_header = (PAK_HEADER*)buffer;

        // 检查文件头
        if (pak_header->version != PACK_FILE_VERSION) return false;
        if (pak_header->encodeing != 1) return false;

        PAK_ENTRY *pak_entry = (PAK_ENTRY*)(buffer + sizeof(PAK_HEADER));

        // 为了保存最后一条的"下一条"，这条特殊的条目的id一定为0
        PAK_ENTRY *end_entry = pak_entry + pak_header->num_entries;
        if (end_entry->id != 0) return false;

        cJSON *root = cJSON_CreateObject();

        //
        for (uint32_t i = 0; i < pak_header->num_entries; i++)
        {
            PAK_ENTRY *next_entry = pak_entry + 1;

            char name[MAX_PATH];
            sprintf(name, "%d", pak_entry->id);

            char *content = (char*)malloc(next_entry->offset - pak_entry->offset + 1);
            memcpy(content, buffer + pak_entry->offset, next_entry->offset - pak_entry->offset);
            content[next_entry->offset - pak_entry->offset] = 0;

            cJSON_AddItemToObject(root, name, cJSON_CreateString(content));
            free(content);

            pak_entry = next_entry;
        }

        char *str = cJSON_Print(root);
        int len = (int)strlen(str);
        cJSON_Delete(root);
        FILE *fp = fopen("locale.json", "wb");
        if (fp)
        {
            fwrite(str, len, 1, fp);
            fclose(fp);
        }
        free(str);
        printf("locale.json生成完成！");
        getchar();
        return true;
    });

    if (!ret)
    {
        printf("请把语言pak文件拖动到exe上面");
        getchar();
    }
}
