# SHA.NET

## Overview 👁️
SHA implementation in pure C# (.NET 7) Available hash algorithms:
- __SHA-1__
- __SHA-224__
- __SHA-256__
- __SHA-384__
- __SHA-512__


## Project description 📋

Project contains two parts:
- __SHA.NET__ - library with all SHA algorithms implementations
- __SHA_Checksum__ - simple program to create a hash value of the file

### SHA.NET
This part contains SHA algorithms implementations. All uses pointers and some performance tricks like _ArrayPool_ or _MethodImpl(MethodImplOptions.AggressiveInlining)_ attribute to be as fast as possible. If You never use pointers in C# You can look at this project to see how to use it. It was something new for me also.

### SHA_Checksum
Simple one-file program which is used to create and print in command line the hash value of the file.

#### Add options to context menu
This program will be hard to use, so we can add some registry entries that allows to create hash values for all files.
To achieve it You will need to run `dotnet fsi config_registry.fsx` in command line. It is important that You have to run cmd with admin priviliges.  
⚠️ Cause this _config_registry.fsx_ script edits Your registry, please look at this file before running.  
⚠️ Always be careful when You editing registry.

How to run ⚙️
- build SHA_Checksum project using `dotnet build -c Release` command
- run `dotnet fsi config_registry.fsx` in command line with admin priviliges
- to use the program, right click on any file and select _SHA Checksum_ option (in Windows 11 this option will be available after clicking _Show more options_ button).