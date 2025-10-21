#define NOMINMAX
#include <iostream>
#include <windows.h>
#include <vector>
#include <algorithm>
#include <TlHelp32.h>
#include <iomanip>
#include <sstream>
#include <tuple>
#include <thread>
#include <mutex>
#include <cstddef>
#include <cstdint>

// Use qualified names to avoid ambiguity with Windows headers

DWORD GetProcessIdByName(const wchar_t* processName)
{
    DWORD processId =0;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);

    if (hSnapshot != INVALID_HANDLE_VALUE)
    {
        PROCESSENTRY32W pe;
        pe.dwSize = sizeof(PROCESSENTRY32W);

        if (Process32First(hSnapshot, &pe))
        {
            do
            {
                if (!_wcsicmp(pe.szExeFile, processName))
                {
                    processId = pe.th32ProcessID;
                    break;
                }
            } while (Process32Next(hSnapshot, &pe));
        }

        CloseHandle(hSnapshot);
    }

    if (processId ==0)
    {
        std::wcout << L"Process " << processName << L" not found." << std::endl;
    }
    else
    {
        std::wcout << L"Process " << processName << L" found with PID: " << processId << std::endl;
    }

    return processId;
}

static void PrintProgress(size_t done, size_t total, size_t success)
{
    const int barWidth =40;
    float progress = (total ==0) ?0.0f : static_cast<float>(done) / static_cast<float>(total);
    int pos = static_cast<int>(progress * barWidth);

    std::ostringstream ss;
    ss << "\r[";
    for (int i =0; i < pos; ++i)
        ss << '#';
    for (int i = pos; i < barWidth; ++i)
        ss << '-';
    ss << "] " << std::setw(3) << static_cast<int>(progress *100.0f) << "% ";
    ss << done << "/" << total << " (OK:" << success << ")";

    std::cout << ss.str() << std::flush;

    if (done == total)
        std::cout << std::endl;
}

std::vector<LPVOID> ScanMemory(HANDLE hProcess, const std::vector<LPVOID>& addressesToScan, int valueToFind)
{
    std::vector<LPVOID> foundAddresses;
    const SIZE_T bufferSize = sizeof(int);

    unsigned int numThreads = std::thread::hardware_concurrency();
    if (numThreads ==0)
        numThreads =1;

    if (addressesToScan.empty())
    {
        // Collect readable committed regions
        std::vector<std::pair<LPVOID, SIZE_T>> regionsToScan;
        MEMORY_BASIC_INFORMATION mbi;
        LPBYTE address = nullptr;

        while (VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi)) !=0)
        {
            if (mbi.State == MEM_COMMIT)
            {
                if (!(mbi.Protect & PAGE_GUARD) && !(mbi.Protect & PAGE_NOACCESS))
                {
                    DWORD protect = mbi.Protect;
                    bool isReadable = (protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY |
                                                  PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) !=0;

                    if (isReadable && mbi.RegionSize >= bufferSize)
                    {
                        regionsToScan.emplace_back(mbi.BaseAddress, mbi.RegionSize);
                    }
                }
            }

            address = static_cast<LPBYTE>(mbi.BaseAddress) + mbi.RegionSize;
            if (address == nullptr)
                break;
        }

        if (regionsToScan.empty())
            return foundAddresses;

        // Partition regions round-robin across threads
        std::vector<std::vector<std::pair<LPVOID, SIZE_T>>> partitions(numThreads);
        for (size_t i =0; i < regionsToScan.size(); ++i)
            partitions[i % numThreads].push_back(regionsToScan[i]);

        std::mutex resultMutex;
        std::vector<std::thread> workers;
        workers.reserve(numThreads);

        for (unsigned int t =0; t < numThreads; ++t)
        {
            workers.emplace_back([&, t]() {
                std::vector<LPVOID> localFound;

                for (const auto& region : partitions[t])
                {
                    LPBYTE baseAddr = static_cast<LPBYTE>(region.first);
                    SIZE_T regionSize = region.second;
                    const SIZE_T maxChunk =4 *1024 *1024; //4 MB
                    SIZE_T offset =0;

                    while (offset < regionSize)
                    {
                        SIZE_T chunk = std::min(maxChunk, regionSize - offset);
                        std::vector<char> buffer(chunk +16);
                        SIZE_T bytesRead =0;
                        LPVOID readAddr = baseAddr + offset;

                        if (ReadProcessMemory(hProcess, readAddr, buffer.data(), chunk, &bytesRead) && bytesRead >= bufferSize)
                        {
                            char* alignedBuffer = reinterpret_cast<char*>((reinterpret_cast<std::uintptr_t>(buffer.data()) +15) & ~static_cast<std::uintptr_t>(15));

                            for (SIZE_T j =0; j + bufferSize <= bytesRead; ++j)
                            {
                                int currentValue;
                                memcpy(&currentValue, alignedBuffer + j, bufferSize);
                                if (currentValue == valueToFind)
                                {
                                    localFound.push_back(reinterpret_cast<LPVOID>(reinterpret_cast<std::uintptr_t>(readAddr) + j));
                                }
                            }
                        }

                        offset += chunk;
                    }
                }

                if (!localFound.empty())
                {
                    std::lock_guard<std::mutex> lk(resultMutex);
                    foundAddresses.insert(foundAddresses.end(), localFound.begin(), localFound.end());
                }
            });
        }

        for (auto& th : workers)
            th.join();
    }
    else
    {
        // For subsequent scans, process provided addresses in parallel
        size_t addrCount = addressesToScan.size();
        if (addrCount ==0)
            return foundAddresses;

        std::vector<std::vector<LPVOID>> partitions(numThreads);
        for (size_t i =0; i < addrCount; ++i)
            partitions[i % numThreads].push_back(addressesToScan[i]);

        std::mutex resultMutex;
        std::vector<std::thread> workers;
        workers.reserve(numThreads);

        for (unsigned int t =0; t < numThreads; ++t)
        {
            workers.emplace_back([&, t]() {
                std::vector<LPVOID> localFound;

                for (LPVOID addr : partitions[t])
                {
                    int currentValue =0;
                    SIZE_T bytesRead =0;
                    if (ReadProcessMemory(hProcess, addr, &currentValue, bufferSize, &bytesRead) && bytesRead == bufferSize)
                    {
                        if (currentValue == valueToFind)
                            localFound.push_back(addr);
                    }
                }

                if (!localFound.empty())
                {
                    std::lock_guard<std::mutex> lk(resultMutex);
                    foundAddresses.insert(foundAddresses.end(), localFound.begin(), localFound.end());
                }
            });
        }

        for (auto& th : workers)
            th.join();
    }

    return foundAddresses;
}

bool UpdateAddresses(HANDLE hProcess, const std::vector<LPVOID>& addresses, int newValue)
{
    if (addresses.empty())
    {
        std::cout << "No addresses to update." << std::endl;
        return false;
    }

    size_t total = addresses.size();
    size_t done =0;
    size_t successCount =0;
    std::vector<std::string> writeResults;
    writeResults.reserve(total);

    PrintProgress(done, total, successCount);

    const SIZE_T bufferSize = sizeof(int);
    for (LPVOID addr : addresses)
    {
        SIZE_T bytesWritten =0;
        bool ok = (WriteProcessMemory(hProcess, addr, &newValue, bufferSize, &bytesWritten) &&
                   bytesWritten == bufferSize);
        if (ok)
        {
            ++successCount;
            std::ostringstream ss;
            ss << " [SUCCESS] Updated address:0x" << std::hex << reinterpret_cast<std::uintptr_t>(addr) << std::dec;
            writeResults.push_back(ss.str());
        }
        else
        {
            std::ostringstream ss;
            ss << " [FAILURE] Failed to write to address:0x" << std::hex << reinterpret_cast<std::uintptr_t>(addr) << std::dec
               << ". Error: " << GetLastError();
            writeResults.push_back(ss.str());
        }

        ++done;
        PrintProgress(done, total, successCount);
    }

    for (const auto& line : writeResults)
        std::cout << line << std::endl;

    return successCount >0;
}

void DisplayAddresses(const std::vector<LPVOID>& addresses, int value)
{
    std::cout << "\nFound " << addresses.size() << " addresses containing the value " << value << ":" << std::endl;
    for (LPVOID addr : addresses)
        std::cout << "0x" << std::hex << reinterpret_cast<std::uintptr_t>(addr) << std::dec << std::endl;
}

int main()
{
    const wchar_t* targetProcessName = L"eldenring.exe";

    std::cout << "Memory Scanner and Updater" << std::endl;
    std::cout << "-------------------------------" << std::endl;
    std::wcout << L"Target Process: " << targetProcessName << std::endl;

    DWORD processId = GetProcessIdByName(targetProcessName);
    if (processId ==0)
    {
        std::cerr << "Cannot proceed without a target PID." << std::endl;
        return 1;
    }

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE |
                                  PROCESS_VM_OPERATION,
                                  FALSE, processId);
    if (hProcess == NULL)
    {
        std::wcout << L"Failed to open process with PID: " << processId << std::endl;
        return 1;
    }

    std::vector<LPVOID> currentAddresses;
    int valueToFind =0;

    while (true)
    {
        std::cout << "\nEnter the integer value to search for: ";
        if (!(std::cin >> valueToFind))
            break;

        currentAddresses = ScanMemory(hProcess, currentAddresses, valueToFind);

        if (currentAddresses.empty())
        {
            std::cout << "No occurrences of value " << valueToFind << " found." << std::endl;
            break;
        }

        DisplayAddresses(currentAddresses, valueToFind);

        std::cout << "\nChoose an option:" << std::endl;
        std::cout << "1. Continue scanning with a new value (narrow results)" << std::endl;
        std::cout << "2. Update found addresses with a new value" << std::endl;
        std::cout << "3. Exit" << std::endl;
        std::cout << "Choice: ";

        int choice =0;
        if (!(std::cin >> choice))
            break;

        if (choice ==2)
        {
            std::cout << "Enter the new value to write to these addresses: ";
            int newValue =0;
            if (!(std::cin >> newValue))
                break;

            if (UpdateAddresses(hProcess, currentAddresses, newValue))
                std::cout << "Memory update completed." << std::endl;
            break;
        }
        else if (choice ==3)
        {
            break;
        }
        // If choice ==1, the loop continues with a new scan
    }

    CloseHandle(hProcess);
    std::cout << "\nOperation finished. Press Enter to exit.";
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    std::cin.get();
    return 0;
}
