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

std::vector<byte> obfuseCode(std::vector<byte>& bin_code)
{
    auto instr_v = decodeBin(bin_code);
/*
    std::cout<<"!!!\n";
    for(auto&& i : instr_v)
    {
        std::cout<<i<<std::endl;
    }
    std::cout<<"!!!\n";*/

    std::vector<std::unique_ptr<AbstractTextObfuscator>> textObfuscators;
//    textObfuscators.push_back(std::make_unique<Jumper>());
//    textObfuscators.push_back(std::make_unique<Shuffler>());
//    textObfuscators.push_back(std::make_unique<Junk>());

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
    out_file.reserve(file_content.size() + 5000); // in order to exclude exclude

    out_file.insert(std::end(out_file), std::begin(file_content), std::begin(file_content) + source_image_header->OptionalHeader.SizeOfHeaders);

    auto* dst_dos_header = getDosHeader(out_file.data());
    if (!dst_dos_header)
        return false;
    auto* dst_image_header = getNtHeader(dst_dos_header);
    if (!dst_image_header)
        return false;


    //copy sections
    IMAGE_SECTION_HEADER* dst_section_header = nullptr;
    IMAGE_SECTION_HEADER* src_section_header = nullptr;

    for (std::size_t i = 0; i < source_image_header->FileHeader.NumberOfSections; i++) {

        //IMAGE_NT_HEADERS64 kostil, need to fix build
        src_section_header = reinterpret_cast<IMAGE_SECTION_HEADER*>(file_content.data() + source_dos_header->e_lfanew + sizeof(IMAGE_NT_HEADERS64) +
                                                                     (sizeof(IMAGE_SECTION_HEADER) * i));

        dst_section_header = reinterpret_cast<IMAGE_SECTION_HEADER*>(out_file.data() + dst_dos_header->e_lfanew + sizeof(IMAGE_NT_HEADERS64) +
                                                                     (sizeof(IMAGE_SECTION_HEADER) * i));
        std::cout << "section " << i << ": " << dst_section_header->Name << ", RVA: " << std::hex
                  << dst_section_header->VirtualAddress << " size of raw data: " << dst_section_header->SizeOfRawData << std::endl;


        if(source_image_header->OptionalHeader.AddressOfEntryPoint >= dst_section_header->VirtualAddress &&
           source_image_header->OptionalHeader.AddressOfEntryPoint <= dst_section_header->VirtualAddress + dst_section_header->Misc.VirtualSize)
        {
            dst_section_header->Characteristics = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;

            auto&& from = file_content.data() + dst_section_header->PointerToRawData;
            std::vector<byte> code{from, from + /*dst_section_header->SizeOfRawData*/ dst_section_header->Misc.VirtualSize};
            auto encoded = obfuseCode(code);

            dst_section_header->Misc.VirtualSize = encoded.size();
            encoded.resize(encoded.size() + (dst_image_header->OptionalHeader.FileAlignment - (encoded.size() % dst_image_header->OptionalHeader.FileAlignment)));//padding with zero
            dst_section_header->SizeOfRawData = encoded.size();

            out_file.insert(std::end(out_file), std::begin(encoded), std::end(encoded)); // .data() + dst_section_header->SizeOfRawData
        }
        else {
            dst_section_header->PointerToRawData = out_file.size();
            out_file.insert(std::end(out_file), file_content.data() + src_section_header->PointerToRawData,
                            file_content.data() + src_section_header->PointerToRawData + src_section_header->SizeOfRawData);
        }


        writeBinFile("test.exe", out_file);

    }

    return true;
}


int main() {


//    auto file_content = readFile("C:\\Users\\danek\\CLionProjects\\untitled1\\cmake-build-debug\\untitled1.exe");
//    auto file_content = readBinFile("C:\\reverse\\hw6\\hello2.exe");
//    auto file_content = readBinFile("C:\\reverse\\graduating\\simple_pe.exe");
//    auto file_content = readBinFile("C:\\reverse\\graduating\\hello2.exe");
//    auto file_content = readBinFile("C:\\reverse\\graduating\\hello3.exe");
//    auto file_content = readBinFile("C:\\reverse\\graduating\\hello_gui64.exe");
    auto file_content = readBinFile("C:\\reverse\\graduating\\hello_big.exe");

    auto* src_dos_header = getDosHeader(file_content.data());
    if (!src_dos_header)
        return -1;
    auto* src_image_header = getNtHeader(src_dos_header);
    if (!src_image_header)
        return -1;

    writePEFile(src_dos_header, src_image_header, file_content);

    return 0;
}
