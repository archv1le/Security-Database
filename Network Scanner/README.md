# Network Scanner

## Description

- This is a simple project, which applies techniques from "nmap" tool for scanning ports and other things from IP addresses and domain names.
- This project was written on Python programming language.

## Usage

- You can scan specific ports like in "nmap", using "-p" flag for it.

```
python main.py target_ip -p 80,443
```

- Or you can scan domain names with multiple flags.

```
python main.py target_ip -p 80,443 -sV --version-light
```

- Or you can scan domain names with multiple options.

```
python main.py target_ip -p 1-1000 -A --osscan-guess
```
