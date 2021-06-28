#include <iostream>
#include <fstream>
#include <vector>
#include "array"
#include "Windows.h"
#include "winnt.h"
#include "ObfuseConfuse/utils.h"
//#include "ObfuseConfuse/Obfuscators/Text/AbstractTextObfuscator.h"
#include "ObfuseConfuse/Obfuscators/Text/Jumper.h"
#include "ObfuseConfuse/Obfuscators/Text/Junk.h"
#include "ObfuseConfuse/Obfuscators/Text/Shuffler.h"
#include "ObfuseConfuse/Obfuscators/Bin/TwoXor.h"

#define IMAGE_DOS_SIGNATURE        0x5A4D        // MZ
//#define IMAGE_OS2_SIGNATURE		0x4E45		// NE
//#define IMAGE_OS2_SIGNATURE_LE	0x4C45		// LE
//#define IMAGE_NT_SIGNATURE		0x50450000	// PE00

enum reloc_type {// взято отсюда https://github.com/trailofbits/pe-parse
    RELOC_ABSOLUTE = 0,
    RELOC_HIGH = 1,
    RELOC_LOW = 2,
    RELOC_HIGHLOW = 3,
    RELOC_HIGHADJ = 4,
    RELOC_MIPS_JMPADDR = 5,
    RELOC_MIPS_JMPADDR16 = 9,
    RELOC_IA64_IMM64 = 9,
    RELOC_DIR64 = 10
};

typedef struct {
    WORD pointerOffset : 12;
    WORD flag : 4;
} FIX_UP, * PFIX_UP;

#pragma comment(linker, "/section:.rdata,RWE")
#pragma pack(push, 1)
struct TRUMP
{
    BYTE body[5];
    BYTE jmp = 0xe8;
    ULONG oldFunc = 0x11223344;
} *PTRUMP;
#pragma pack(pop)


HMODULE destImageBase = NULL;
TRUMP trump;


using byte_t = unsigned char;

std::vector<byte_t> readBinFile(const std::string& file) {
    std::ifstream input(file, std::ios::binary);

    // copies all data into buffer
    std::vector<byte_t> buffer(std::istreambuf_iterator<char>(input), {});
    return buffer;
}


IMAGE_DOS_HEADER* getDosHeader(byte_t* bytes) {
    auto* dos_header = reinterpret_cast<IMAGE_DOS_HEADER*>(bytes);

    if (dos_header->e_magic == IMAGE_DOS_SIGNATURE) {
        std::cout << "DOS header ok\n";
    }
    else {
        std::cout << "Error: DOS header is incorrect\n";
        return nullptr;
    }
    return dos_header;
}

IMAGE_NT_HEADERS* getNtHeader(IMAGE_DOS_HEADER* dos_header) {
    auto* image_header = reinterpret_cast<IMAGE_NT_HEADERS*>(reinterpret_cast<byte*>(dos_header) +
                                                             dos_header->e_lfanew);
    if (image_header->Signature != IMAGE_NT_SIGNATURE) {
        std::cout << "Error: PE header is incorrect\n";
        return nullptr;
    }

    std::cout << "PE header ok\n";

    return image_header;
}


DWORD getPageSize()
{
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);

    return sysInfo.dwPageSize;
}

bool prepareProcMemory(IMAGE_DOS_HEADER* source_dos_header, IMAGE_NT_HEADERS* source_image_header, std::vector<byte>& file_content, byte_t* proc) {
    //copy headers
    memcpy(proc, file_content.data(), source_image_header->OptionalHeader.SizeOfHeaders);

    //copy sections
    IMAGE_SECTION_HEADER* section_header = nullptr;
    for (std::size_t i = 0; i < source_image_header->FileHeader.NumberOfSections; i++) {
        section_header = reinterpret_cast<IMAGE_SECTION_HEADER*>(file_content.data() + source_dos_header->e_lfanew +sizeof(IMAGE_NT_HEADERS) +
                                                                 (sizeof(IMAGE_SECTION_HEADER) * i));
        std::cout << "section " << i << ": " << section_header->Name << ", RVA: " << std::hex
                  << section_header->VirtualAddress << std::endl;

        //source_image_header->OptionalHeader.ImageBase +
        memcpy(proc + section_header->VirtualAddress,
               file_content.data() + section_header->PointerToRawData,
               section_header->SizeOfRawData);

        DWORD old_permission;
        for (int i = 0; i < section_header->SizeOfRawData; i += getPageSize())
        {
            if (!VirtualProtect(reinterpret_cast<LPVOID>(proc + section_header->VirtualAddress + i), 1, PAGE_EXECUTE_READWRITE,
                                &old_permission)) {
                std::cerr << "Error: could not change protection" << std::endl;
                return false;
            }
        }

    }

    return true;
}


bool writeBinFile11(const std::string& file, std::vector<byte> const& data) {
    std::ofstream out(file, std::ios::binary);

    for(auto&& it : data)
    {
        out<<it;
    }
    out.close();
    return true;
}


std::vector<byte> obfuseCode(std::vector<byte>& bin_code)
{
    auto instr_v = decodeBin(bin_code);

    for(auto&& i : instr_v)
    {
        std::cout<<i<<std::endl;
    }

    std::vector<std::unique_ptr<AbstractTextObfuscator>> textObfuscators;
    textObfuscators.push_back(std::make_unique<Jumper>());
    textObfuscators.push_back(std::make_unique<Shuffler>());
    textObfuscators.push_back(std::make_unique<Junk>());

    for(auto&& it : textObfuscators)
    {
        instr_v = it->process(instr_v);
    }

    writeTextFile("list.asm", createCodeFor64(instr_v));

    fasm("list.asm");

    auto bin = readFile("list.bin");

//    std::vector<std::unique_ptr<AbstractBinObfuscator>> binObfuscators;
    std::unique_ptr<TwoXor> binObfuscator{std::make_unique<TwoXor>()};
    auto encoded = binObfuscator->encode(bin);
//    printHex(encoded);

    auto separated_listing = binObfuscator->addAsmStub(encoded);
//    separated_listing.code_before_start
    auto listening = createCodeFor64(separated_listing);
//    std::vector<std::string> c = code_data.first;
//    c.insert(std::end(c), std::begin(code_data.second), std::end(code_data.second));
//    auto listening = createCodeFor64(c);

    writeTextFile("shellcode.asm", listening);
    build("shellcode.asm");
    bin = readFile("shellcode.bin");
    return bin;
}

bool writePEFile(IMAGE_DOS_HEADER* source_dos_header, IMAGE_NT_HEADERS* source_image_header, std::vector<byte>& file_content) {
    //copy headers

    std::vector<byte> out_file;
    out_file.reserve(file_content.size());

    out_file.resize(out_file.size() + source_image_header->OptionalHeader.SizeOfHeaders);
    memcpy(out_file.data(), file_content.data(), source_image_header->OptionalHeader.SizeOfHeaders);

    //copy sections
    IMAGE_SECTION_HEADER* section_header = nullptr;
    for (std::size_t i = 0; i < source_image_header->FileHeader.NumberOfSections; i++) {

        //IMAGE_NT_HEADERS64 kostil, nees to fix
        section_header = reinterpret_cast<IMAGE_SECTION_HEADER*>(file_content.data() + source_dos_header->e_lfanew +sizeof(IMAGE_NT_HEADERS64) +
                                                                 (sizeof(IMAGE_SECTION_HEADER) * i));
        std::cout << "section " << i << ": " << section_header->Name << ", RVA: " << std::hex
                  << section_header->VirtualAddress << " size of raw data: " << section_header->SizeOfRawData<<std::endl;

        if(i == 0)
        {
            auto&& from =  file_content.data() + section_header->PointerToRawData;
            std::vector<byte> code{from,from + /*section_header->SizeOfRawData*/ section_header->Misc.VirtualSize};
            auto encoded = obfuseCode(code);
            if(encoded.size() < section_header->SizeOfRawData)
            {
                encoded.resize(section_header->SizeOfRawData);
//                memset(encoded.data() + encoded.size(), 0 ,section_header->SizeOfRawData - encoded.size() );
            }
            /*else if(encoded.size() > section_header->SizeOfRawData)
            {
                section_header->SizeOfRawData += 0x200;
                memset(encoded.data() + encoded.size(), 0 ,section_header->SizeOfRawData - encoded.size() );
            }*/
            out_file.insert(std::end(out_file), encoded.data(),encoded.data() + section_header->SizeOfRawData);
        }
        else {
            out_file.insert(std::end(out_file), file_content.data() + section_header->PointerToRawData,
                            file_content.data() + section_header->PointerToRawData + section_header->SizeOfRawData);
        }


        writeBinFile("test.exe", out_file);

    }

    return true;
}


int main() {


//    auto file_content = readFile("C:\\Users\\danek\\CLionProjects\\untitled1\\cmake-build-debug\\untitled1.exe");
//    auto file_content = readBinFile("C:\\reverse\\hw6\\hello2.exe");
//    auto file_content = readBinFile("C:\\reverse\\graduating\\simple_pe.exe");
    auto file_content = readBinFile("C:\\reverse\\graduating\\hello2.exe");

    auto* src_dos_header = getDosHeader(file_content.data());
    if (!src_dos_header)
        return -1;
    auto* src_image_header = getNtHeader(src_dos_header);
    if (!src_image_header)
        return -1;

//    byte_t* proc = new byte_t[src_image_header->OptionalHeade
//    r.SizeOfImage];

    writePEFile(src_dos_header, src_image_header, file_content);
//    if (!prepareProcMemory(src_dos_header, src_image_header, file_content, proc))
//        return -1;
/*
    auto* dst_dos_header = getDosHeader(proc);
    auto* dst_image_header = getNtHeader(dst_dos_header);

    DWORD old_image_base = dst_image_header->OptionalHeader.ImageBase;
    dst_image_header->OptionalHeader.ImageBase = reinterpret_cast<DWORD>(proc);

    proceccImport(dst_image_header);
    processRealloc(dst_image_header, old_image_base);
*/
//    HookGetModuleHandle();

//    auto ret = GetModuleHandleA(NULL);
//    std::cerr << std::hex << "ret: " << ret << std::endl;
/*
    DWORD* va_entry_point = reinterpret_cast<DWORD*>(dst_image_header->OptionalHeader.ImageBase +
                                                     dst_image_header->OptionalHeader.AddressOfEntryPoint);

    __asm { mov eax, va_entry_point }
    __asm { jmp eax }
*/
    return 0;
}
