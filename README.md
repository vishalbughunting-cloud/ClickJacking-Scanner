# ClickJacking-Scanner
Advance Click jacking scanner detect vulnerability 
Method 1: Using Go Build (Recommended)
Install Go from https://golang.org/dl/

## Installation
download files 

Open Command Prompt in the folder

Build for Windows:

cmd
go build -o clickjack_batch_fast.exe clickjack_batch_fast.go


# Clickjack Scanner

A fast, lightweight clickjacking vulnerability scanner written in Go. This tool automatically detects if websites are vulnerable to clickjacking attacks by checking for missing security headers.

## Features

- 🚀 **Fast Scanning** - Concurrent scanning with timeout support
- 🔍 **Auto-Detection** - Automatically detects GET/POST methods
- 📊 **Multiple Outputs** - Saves results in TXT and JSON formats
- 🎯 **PoC Generation** - Automatically generates Proof-of-Concept HTML files
- 📁 **Batch Processing** - Scan multiple URLs from a file
- ⚡ **Standalone Executable** - No dependencies required



### Method 2: Build from Source
```bash
# Prerequisite: Install Go
git clone https://github.com/yourusername/clickjack-scanner
cd clickjack-scanner
go build -o clickjack_batch_fast.exe clickjack_batch_fast.go
Usage
Single URL Scan


<img width="938" height="330" alt="click jacking" src="https://github.com/user-attachments/assets/8886d053-7490-4aef-a6cc-122aaa6fbd94" />


Single URL Scan
cmd
clickjack_batch_fast.exe  https://example.com

Multi URL Scan
clickjack_batch_fast.exe urls.txt

