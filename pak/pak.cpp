#include <stdint.h>
#include <windows.h>
#include <stdio.h>

#include "cJSON.h"
#include "md5.h"

#include <Shlobj.h>
#include <Shlwapi.h>
#pragma comment(lib, "shlwapi.lib")


#include <string>
#include <map>
#include <vector>


template<typename Function>
bool LoadFromResource(const char *type, const char *name, Function f)
{
    bool result = false;
    HMODULE hInstance = GetModuleHandle(NULL);
    HRSRC res = FindResourceA(hInstance, name, type);
    if (res)
    {
        HGLOBAL header = LoadResource(hInstance, res);
        if (header)
        {
            const char *data = (const char*)LockResource(header);
            DWORD size = SizeofResource(hInstance, res);
            if (data)
            {
                f(data, size);
                result = true;
                UnlockResource(header);
            }
        }
        FreeResource(header);
    }

    return result;
}

template<typename Function>
void mapfile(const char *file, Function f)
{
    HANDLE hfile = CreateFileA(file,
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL, NULL);
    if (hfile == INVALID_HANDLE_VALUE)
    {
        return;
    }
    BY_HANDLE_FILE_INFORMATION file_info;
    GetFileInformationByHandle(hfile, &file_info);
    unsigned long file_size = file_info.nFileSizeLow;
    HANDLE hfilemap = CreateFileMapping(hfile, NULL, PAGE_READONLY, 0, 0, NULL);
    CloseHandle(hfile);
    unsigned char *buf = (unsigned char*)MapViewOfFile(hfilemap, FILE_MAP_READ, 0, 0, 0);
    CloseHandle(hfilemap);

    f(buf, file_size);

    UnmapViewOfFile(buf);
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

void unpack()
{
    std::map <std::string, std::string> namemap;

    LoadFromResource("json", "resource_ids", [&](const char *buffer, DWORD size)
    {
        cJSON *root = cJSON_Parse((char*)buffer);
        if (root)
        {
            cJSON *subitem = root->child;
            while (subitem)
            {
                int j = 0;
                while (subitem->valuestring[j] != '\0')
                {
                    if (subitem->valuestring[j] == '/') subitem->valuestring[j] = '\\';
                    j++;
                }
                namemap.insert({ subitem->string, subitem->valuestring });

                subitem = subitem->next;
            }

        }
    });

    printf("开始解包 resources.pak\n");
    mapfile("resources.pak", [&](unsigned char *buffer, unsigned long size) {

        PAK_HEADER *pak_header = (PAK_HEADER*)buffer;

        // 检查文件头
        if (pak_header->version != PACK_FILE_VERSION) return;
        if (pak_header->encodeing != 1) return;

        PAK_ENTRY *pak_entry = (PAK_ENTRY*)(buffer + sizeof(PAK_HEADER));

        // 为了保存最后一条的"下一条"，这条特殊的条目的id一定为0
        PAK_ENTRY *end_entry = pak_entry + pak_header->num_entries;
        if (end_entry->id != 0) return;


        char folder[MAX_PATH] = { 0 };
        GetModuleFileNameA(NULL, folder, MAX_PATH);
        PathRemoveFileSpecA(folder);

        //
        cJSON *root = cJSON_CreateObject();

        for (uint32_t i = 0; i < pak_header->num_entries; i++)
        {
            PAK_ENTRY *next_entry = pak_entry + 1;

            MD5 md5(buffer + pak_entry->offset, next_entry->offset - pak_entry->offset);
            std::string xxx = md5.toStr();

            char path[MAX_PATH];
            if (namemap.find(xxx) != namemap.end())
            {
                wsprintfA(path, "resources\\%s", namemap[xxx].c_str());
            }
            else
            {
                char html1[] = "<!doctype html>";
                size_t html1_len = strlen(html1);

                char html2[] = "<html>";
                size_t html2_len = strlen(html2);

                char html3[] = "<link";
                size_t html3_len = strlen(html3);

                char js1[] = "// ";
                size_t js1_len = strlen(js1);

                char css1[] = "/*";
                size_t css1_len = strlen(css1);

                char json1[] = "{";
                size_t json1_len = strlen(json1);

                BYTE png[] = {0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A};
                size_t png_len = sizeof(png);

                if (memcmp(buffer + pak_entry->offset, html1, min(next_entry->offset - pak_entry->offset, html1_len)) == 0)
                {
                    wsprintfA(path, "resources\\unknown\\%d.html", pak_entry->id);
                }
                else if(memcmp(buffer + pak_entry->offset, html2, min(next_entry->offset - pak_entry->offset, html2_len)) == 0)
                {
                    wsprintfA(path, "resources\\unknown\\%d.html", pak_entry->id);
                }
                else if(memcmp(buffer + pak_entry->offset, html3, min(next_entry->offset - pak_entry->offset, html3_len)) == 0)
                {
                    wsprintfA(path, "resources\\unknown\\%d.html", pak_entry->id);
                }
                else if(memcmp(buffer + pak_entry->offset, js1, min(next_entry->offset - pak_entry->offset, js1_len)) == 0)
                {
                    wsprintfA(path, "resources\\unknown\\%d.js", pak_entry->id);
                }
                else if(memcmp(buffer + pak_entry->offset, css1, min(next_entry->offset - pak_entry->offset, css1_len)) == 0)
                {
                    wsprintfA(path, "resources\\unknown\\%d.css", pak_entry->id);
                }
                else if(memcmp(buffer + pak_entry->offset, json1, min(next_entry->offset - pak_entry->offset, json1_len)) == 0)
                {
                    wsprintfA(path, "resources\\unknown\\%d.json", pak_entry->id);
                }
                else if(memcmp(buffer + pak_entry->offset, png, min(next_entry->offset - pak_entry->offset, png_len)) == 0)
                {
                    wsprintfA(path, "resources\\unknown\\%d.png", pak_entry->id);
                }
                else
                {
                    wsprintfA(path, "resources\\unknown\\%d", pak_entry->id);
                }
                //printf("%X %s %X %d\n", pak_entry->id, xxx.c_str(), pak_entry->offset, next_entry->offset - pak_entry->offset);
            }

            char path2[MAX_PATH];
            strcpy(path2, path);
            PathRemoveFileSpecA(path2);
            ::PathCombineA(path2, folder, path2);
            SHCreateDirectoryExA(NULL, path2, NULL);

            printf("写入 %s\n", path);
            FILE *fp = fopen(path, "wb");
            if (fp)
            {
                fwrite(buffer + pak_entry->offset, next_entry->offset - pak_entry->offset, 1, fp);
                fclose(fp);
            }

            char name[MAX_PATH];
            wsprintfA(name, "%d", pak_entry->id);
            cJSON_AddItemToObject(root, name, cJSON_CreateString(path));

            pak_entry = next_entry;
        }

        char *str = cJSON_Print(root);
        int len = (int)strlen(str);
        cJSON_Delete(root);
        printf("生成元数据 %s ，请勿修改此文件。\n", "resources.json");
        FILE *fp = fopen("resources.json", "wb");
        if (fp)
        {
            fwrite(str, len, 1, fp);
            fclose(fp);
        }
        free(str);
    });
}

void pack()
{
    printf("开始打包 resources.pak\n");
    mapfile("resources.json", [&](unsigned char *buffer, unsigned long size) {
        cJSON *root = cJSON_Parse((char*)buffer);
        if (root)
        {
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


                printf("读取 %s\n", subitem->valuestring);
                mapfile(subitem->valuestring, [&](unsigned char *buffer, unsigned long size) {
                    content_buffer.insert(content_buffer.end(), buffer, buffer + size);
                });

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

            printf("生成 resources.pak\n");
            FILE *fp = fopen("resources.pak", "wb");
            if (fp)
            {
                fwrite(&header, sizeof(header), 1, fp);
                fwrite(&entrys[0], sizeof(PAK_ENTRY) * entrys.size(), 1, fp);
                fwrite(&content_buffer[0], content_buffer.size(), 1, fp);
                fclose(fp);
            }
        }
    });
}

int main(int argc, char *argv[])
{
    FILE *fp = fopen("resources.json", "rb");
    if (fp)
    {
        fclose(fp);
        printf("找到元数据，进入打包模式\n");
        pack();
        printf("打包完成\n");
        getchar();
    }
    else
    {
        FILE *fp = fopen("resources.pak", "rb");
        if (fp)
        {
            fclose(fp);
            printf("没有找到元数据，进入解包模式\n");
            unpack();
            printf("解包完成\n");
            getchar();
        }
        else
        {
            printf("把resources.pak放到当前目录开始工作");
            getchar();
        }
    }
}
