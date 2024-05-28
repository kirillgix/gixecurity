import "pe"

rule SuspiciousDataCollector
{
    meta:
        description = "Detects files that potentially collect user data"
        author = "ks"
        date = "2024-05-27"

    strings:
        // strings related to geo
        $geo1 = "geolocation"
        $geo2 = "getCurrentPosition"
        $geo3 = "watchPosition"
        $geo4 = "latitude"
        $geo5 = "longitude"

        // strings related user actions
        $action1 = "keylogger"
        $action2 = "mouseclick"
        $action3 = "mousemove"
        $action4 = "keystroke"
        $action5 = "clipboard"

        // strings related network requests
        $network1 = "XMLHttpRequest"
        $network2 = "fetch"
        $network3 = "WebSocket"
        $network4 = "POST"
        $network5 = "GET"

        // strings related data storage
        $storage1 = "localStorage"
        $storage2 = "sessionStorage"
        $storage3 = "indexedDB"
        $storage4 = "cookie"
        $storage5 = "setItem"

        // string related encryption
        $crypto1 = "CryptoJS"
        $crypto2 = "OpenSSL"
        $crypto3 = "AES"
        $crypto4 = "RSA"
        $crypto5 = "encrypt"

    condition:
        // PE header check (if applicable)
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and

        // checking  rows from different categories
        (
            2 of ($geo*) or
            2 of ($action*) or
            2 of ($network*) or
            2 of ($storage*) or
            2 of ($crypto*)
        ) and

        // verification of imports (if applicable)
        (
            pe.imports("wininet.dll", "InternetOpenA") or
            pe.imports("wininet.dll", "InternetOpenUrlA") or
            pe.imports("wininet.dll", "InternetReadFile") or
            pe.imports("ws2_32.dll", "socket") or
            pe.imports("ws2_32.dll", "connect") or
            pe.imports("advapi32.dll", "CryptAcquireContextA") or
            pe.imports("advapi32.dll", "CryptCreateHash") or
            pe.imports("advapi32.dll", "CryptHashData")
        ) and

        filesize > 500KB
}

rule RansomwareIndicators
{
    meta:
        description = "Detects potential ransomware behavior"
        author = "ks"
        date = "2024-05-27"
    strings:
        // extensions specific to ransomware
        $extension1 = ".encrypted"
        $extension2 = ".locked"
        $extension3 = ".crypto"
        $extension4 = ".crypted"
        $extension5 = ".enc"
        $extension6 = ".cry"
        $extension7 = ".lock"
        $extension8 = ".pay"
        $extension9 = ".payme"
        $extension10 = ".paycrypt"
        $extension11 = ".id_"
        $extension12 = /\.id-[a-z0-9]{8}/

        // ransomware characteristic lines
        $ransom_note1 = "your files have been encrypted"
        $ransom_note2 = "all your files are encrypted"
        $ransom_note3 = "decrypt your files"
        $ransom_note4 = "payment instruction"
        $ransom_note5 = "bitcoin payment"
        $ransom_note6 = "contact us"
        $ransom_note7 = "ransomware"
        $ransom_note8 = "decryptor"
        $ransom_note9 = "restore your files"
        $ransom_note10 = "recover your data"
        $ransom_note11 = "private key"
        $ransom_note12 = "unique key"

        // ransomware indicator files
        $file_indicator1 = "ransom_note.txt"
        $file_indicator2 = "how_to_decrypt.txt"
        $file_indicator3 = "recover_instructions.txt"
        $file_indicator4 = "decrypt_instructions.html"
        $file_indicator5 = "decryptor.exe"
        $file_indicator6 = "decrypt_tool.exe"

        // ransomware-related commands
        $command1 = "vssadmin.exe Delete Shadows"
        $command2 = "wbadmin delete catalog"
        $command3 = "bcdedit /set {default} recoveryenabled No"
        $command4 = "bcdedit /set {default} bootstatuspolicy ignoreallfailures"
        $command5 = /rundll32\.exe.+,#[0-9]+/
    condition:
        // extension check
        any of ($extension*) or
        // ransom lines check
        any of ($ransom_note*) or
        // file indicator check
        any of ($file_indicator*) or
        // command check
        any of ($command*)
}

rule KeyloggerBehavior
{
    meta:
        description = "Detects behavior indicative of keyloggers"
        author = "ks"
        date = "2024-05-27"
    strings:
        // strings related to keylogger
        $key1 = "GetAsyncKeyState"
        $key2 = "GetForegroundWindow"
        $key3 = "GetWindowText"
        $key4 = "SetWindowsHookEx"
        $key5 = "WH_KEYBOARD"
        $key6 = "WH_KEYBOARD_LL"
        $key7 = "GetKeyboardState"
        $key8 = "ShowWindow"
        $key9 = "SendInput"
        $key10 = "SendMessage"
        $key11 = "PostMessage"
        $key12 = "NtUserGetAsyncKeyState"
        $key13 = "NtUserGetKeyState"
        $key14 = "NtUserGetKeyboardState"
        $key15 = "NtUserMapVirtualKeyEx"
        $key16 = "GetRawInputData"
        $key17 = "RegisterHotKey"
        $key18 = "UnregisterHotKey"
        $key19 = "ReadProcessMemory"
        $key20 = "WriteProcessMemory"
        $key21 = "OpenProcess"

        // byte sequences characteristic of keyloggers
        $byte1 = { 8B FF 55 8B EC 83 EC 14 53 56 57 8B 7D 0C 33 DB 85 FF }
        $byte2 = { 6A 0C 68 0A 00 00 00 E8 79 8E 00 00 50 E8 8D 00 00 00 }

        // regular expressions for detecting keyloggers in different languages
        $regex1 = /[kK]ey[lL]og(ger|ging)/
        $regex2 = /[kK]eystroke[s]?/
        $regex3 = /[Pp]assword[s]?/
        $regex4 = /[Cc]redentials/
        $regex5 = /input capture/i
        $regex6 = /screen capture/i

        // file names characteristic of keyloggers
        $file1 = "keylogger.exe"
        $file2 = "stealer.exe"
        $file3 = "keylog.txt"
        $file4 = "passwords.txt"
        $file5 = "credentials.txt"
        $file6 = "keystrokes.log"
        $file7 = "keylog.dll"
        $file8 = "logger.dll"

        // keylogger configuration components
        $config1 = "log_interval"
        $config2 = "capture_screenshot"
        $config3 = "send_email"
        $config4 = "smtp_server"
        $config5 = "email_recipient"
        $config6 = "ftp_server"
        $config7 = "ftp_username"
        $config8 = "ftp_password"
        $config9 = "hide_window"
        $config10 = "auto_start"

        // name of classes specific to c# keyloggers
        $cs1 = "System.Windows.Forms.KeyEventArgs"
        $cs2 = "Microsoft.Win32.RegistryKey"
        $cs3 = "System.Diagnostics.Process"
        $cs4 = "System.IO.StreamWriter"
        $cs5 = "System.Net.Mail.SmtpClient"

    condition:
        // check for suspicious strings, byte sequences or regular expressions
        3 of ($key*) or
        any of ($byte1, $byte2) or
        any of ($regex1, $regex2, $regex3, $regex4, $regex5, $regex6) or
        any of ($file1, $file2, $file3, $file4, $file5, $file6, $file7, $file8) or
        any of ($config1, $config2, $config3, $config4, $config5, $config6, $config7, $config8, $config9, $config10) or
        any of ($cs1, $cs2, $cs3, $cs4, $cs5)
}

rule WebShellPattern
{
    meta:
        description = "Detects common web shell patterns"
        author = "ks"
        date = "2024-05-27"
    strings:
        // shell command calls
        $cmd1 = "eval(base64_decode("
        $cmd2 = "system("
        $cmd3 = "shell_exec("
        $cmd4 = "/bin/sh"
        $cmd5 = "exec("
        $cmd6 = "<?php"
        $cmd7 = "passthru("
        $cmd8 = "popen("
        $cmd9 = "proc_open("
        $cmd10 = "file_get_contents("
        $cmd11 = "php_uname("
        $cmd12 = "getenv("
        $cmd13 = "assert("
        $cmd14 = "include("
        $cmd15 = "require("
        $cmd16 = "dl("
        $cmd17 = "fwrite("
        $cmd18 = "fopen("
        $cmd19 = "chmod("
        $cmd20 = "chown("
        $cmd21 = "shellcode"
        $cmd22 = "backdoor"

        // encrypted or obfuscated strings
        $encoded1 = "Z2V0c3lzdGVtKCk=" // Base64 encoded "getsystem()"
        $encoded2 = "c2hlbGxfZXhlYygp" // Base64 encoded "shell_exec()"
        $encoded3 = "ZXhwbG9yZQ==" // Base64 encoded "explore"
        $encoded4 = "cGFzc3RocnUoKQ==" // Base64 encoded "passthru()"
        $encoded5 = "b3BlbiAoY21kKQ==" // Base64 encoded "open (cmd)"
        $encoded6 = "aW5qZWN0aW9uX3dpbmRvdw==" // Base64 encoded "injection_window"

        // regular expressions for detecting obfuscated commands
        $regex1 = /eval\(base64_decode\([^)]+\)\)/
        $regex2 = /assert\(base64_decode\([^)]+\)\)/
        $regex3 = /system\(base64_decode\([^)]+\)\)/

        // encrypted strings characteristic of web shells
        $cipher1 = "openssl_decrypt"
        $cipher2 = "mcrypt_decrypt"
        $cipher3 = "gzinflate"
        $cipher4 = "gzuncompress"
        $cipher5 = "gzdecode"
        $cipher6 = "zlib_decode"

        // examples of web shell indicator files
        $indicator1 = "webshell.php"
        $indicator2 = "connect.php"
        $indicator3 = "cmd.php"
        $indicator4 = "config.php"
        $indicator5 = "shell.php"
        $indicator6 = "backdoor.php"
        $indicator7 = "eval.php"
        $indicator8 = "info.php"
        $indicator9 = "admin.php"
        $indicator10 = "upload.php"

    condition:
        any of ($cmd1, $cmd2, $cmd3, $cmd4, $cmd5, $cmd6, $cmd7, $cmd8, $cmd9, $cmd10, $cmd11, $cmd12, $cmd13, $cmd14, $cmd15, $cmd16, $cmd17, $cmd18, $cmd19, $cmd20, $cmd21, $cmd22) or
        any of ($encoded1, $encoded2, $encoded3, $encoded4, $encoded5, $encoded6) or
        any of ($cipher1, $cipher2, $cipher3, $cipher4, $cipher5, $cipher6) or
        any of ($regex1, $regex2, $regex3) or
        any of ($indicator1, $indicator2, $indicator3, $indicator4, $indicator5, $indicator6, $indicator7, $indicator8, $indicator9, $indicator10)
}

rule CryptoMiner
{
    meta:
        description = "Detects potential cryptocurrency mining software"
        author = "ks"
        date = "2024-05-27"
    strings:
        // miner commands
        $cmd1 = "stratum+tcp://"
        $cmd2 = "stratum2+tcp://"
        $cmd3 = "pool.minexmr.com"
        $cmd4 = "xmr-stak"
        $cmd5 = "xmrig"
        $cmd6 = "ethminer"
        $cmd7 = "ccminer"
        $cmd8 = "cgminer"
        $cmd9 = "bfgminer"
        $cmd10 = "minerd"
        $cmd11 = "miner.exe"
        $cmd12 = "cpuminer"

        // potentially malicious configuration files
        $config1 = "config.json"
        $config2 = "pools.txt"
        $config3 = "start.bat"
        $config4 = "start.sh"

        // typical mining algorithms
        $algo1 = "cryptonight"
        $algo2 = "equihash"
        $algo3 = "ethash"
        $algo4 = "scrypt"
        $algo5 = "blake2s"
        $algo6 = "lyra2v2"
        $algo7 = "verthash"

        // encrypted strings
        $enc1 = "bm9uY2VnZQ==" // base64 encoded "noncege"
        $enc2 = "dXNlcm5hbWU=" // base64 encoded "username"
        $enc3 = "cGFzc3dvcmQ=" // base64 encoded "password"
    condition:
        (2 of ($cmd*)) or
        (1 of ($config*) and 1 of ($cmd*)) or
        (1 of ($algo*) and 1 of ($cmd*)) or
        (1 of ($enc*) and 1 of ($cmd*))
}

rule Comprehensive_RAT_Detection_Linux {
    meta:
        description = "Comprehensive rule for detecting RAT files on Linux"
        author = "ks"
        date = "2024-05-27"
        version = "1.0"
        hash1 = "7f3f1d5e2ab4e9c8c2f5e6d7c8b9a1a"
        hash2 = "8e4f2c3b5a6d7c8b9a1a2b3c4d5e6f"
        reference1 = "https://example.com/rat_analysis_report"
        reference2 = "https://example.com/rat_indicators_of_compromise"

    strings:
        $rat01 = "NjRAT" nocase
        $rat02 = "DarkComet" nocase
        $rat03 = "Poison Ivy" nocase
        $rat04 = "Gh0st RAT" nocase
        $rat05 = "Blackshades" nocase
        $rat06 = "Cybergate" nocase
        $rat07 = "Xtreme RAT" nocase
        $rat08 = "Imminent Monitor" nocase
        $rat09 = "NetWire" nocase
        $rat10 = "Quasar" nocase
        $rat11 = "Remcos" nocase
        $rat12 = "Havex" nocase
        $rat13 = "Konni" nocase
        $rat14 = "Revenge RAT" nocase
        $rat15 = "Adwind" nocase
        $rat16 = "JSocket" nocase
        $rat17 = "jSpy" nocase
        $rat18 = "AlienSpy" nocase
        $rat19 = "Cerberus" nocase
        $rat20 = "Nanocore" nocase
        $rat21 = "Asyncrat" nocase
        $rat22 = "Hawkeye" nocase
        $rat23 = "Luminosity Link" nocase
        $rat24 = "Plasma RAT" nocase
        $rat25 = "Venom RAT" nocase

        $elf = { 7F 45 4C 46 }

        $func01 = "XOpenDisplay"
        $func02 = "XCreateWindow"
        $func03 = "XSelectInput"
        $func04 = "XMapWindow"
        $func05 = "XNextEvent"
        $func06 = "XLookupKeysym"
        $func07 = "socket"
        $func08 = "bind"
        $func09 = "listen"
        $func10 = "accept"
        $func11 = "recv"
        $func12 = "send"
        $func13 = "popen"
        $func14 = "system"
        $func15 = "fork"
        $func16 = "execve"
        $func17 = "mmap"
        $func18 = "ptrace"
        $func19 = "dlopen"
        $func20 = "dlsym"
        $func21 = "fopen"
        $func22 = "fwrite"
        $func23 = "fclose"
        $func24 = "chmod"
        $func25 = "chown"
        $func26 = "mkdir"
        $func27 = "unlink"
        $func28 = "readdir"
        $func29 = "opendir"
        $func30 = "closedir"
        $func31 = "gethostbyname"
        $func32 = "inet_aton"
        $func33 = "connect"
        $func34 = "write"
        $func35 = "read"
        $func36 = "execl"
        $func37 = "execlp"
        $func38 = "execle"
        $func39 = "execv"
        $func40 = "execvp"
        $func41 = "dup2"
        $func42 = "setuid"
        $func43 = "setgid"
        $func44 = "kill"
        $func45 = "chmod"
        $func46 = "chown"
        $func47 = "rename"
        $func48 = "symlink"
        $func49 = "fchmod"
        $func50 = "fchown"

        $pdb01 = "/home/*/.config/autostart/*"
        $pdb02 = "/tmp/*"
        $pdb03 = "/var/tmp/*"
        $pdb04 = "/usr/local/bin/*"
        $pdb05 = "/usr/local/sbin/*"
        $pdb06 = "/usr/bin/*"
        $pdb07 = "/usr/sbin/*"
        $pdb08 = "/bin/*"
        $pdb09 = "/sbin/*"
        $pdb10 = "/opt/*"

    condition:
        $elf at 0 and
        filesize < 20MB and
        (
            5 of ($rat*) or
            15 of ($func*) or
            2 of ($pdb*)
        )
}

rule ExploitKitDetection3 {
    meta:
        description = "Advanced rule for detecting Exploit Kits"
        author = "ks"
        date = "2024-05-27"
        version = "3.0"
        reference1 = "https://example.com/exploit_kit_analysis"
        reference2 = "https://example.com/exploit_kit_indicators"

    strings:
        // Obfuscated JavaScript patterns
        $obf_js1 = /eval\(function\(p,a,c,k,e,d\)/ nocase
        $obf_js2 = /var\s+[a-zA-Z_$][a-zA-Z0-9_$]*\s*=\s*\[\"\\x[0-9a-fA-F]+\"\];/ nocase
        $obf_js3 = /var\s+[a-zA-Z_$][a-zA-Z0-9_$]*\s*=\s*\{\"[a-zA-Z0-9_$]+\":\"[a-zA-Z0-9_$]+\"\};/ nocase
        $obf_js4 = /var\s+[a-zA-Z_$][a-zA-Z0-9_$]*\s*=\s*\"\\x[0-9a-fA-F]+\";/ nocase
        $obf_js5 = /var\s+[a-zA-Z_$][a-zA-Z0-9_$]*\s*=\s*\"\\u[0-9a-fA-F]{4}\";/ nocase

        // Suspicious function calls and patterns
        $sus_func1 = "document.createElement(\"script\")" nocase
        $sus_func2 = "document.write(unescape(" nocase
        $sus_func3 = "window.execScript" nocase
        $sus_func4 = "ActiveXObject(\"WScript.Shell\")" nocase
        $sus_func5 = "new Function(atob(" nocase
        $sus_func6 = "document.body.appendChild(" nocase
        $sus_func7 = "document.getElementsByTagName(\"head\")[0].appendChild(" nocase
        $sus_func8 = "window.navigator.userAgent.toLowerCase()" nocase

        // Shellcode patterns
        $shellcode1 = /\x64\xa1\x30\x00\x00\x00/ nocase
        $shellcode2 = /\x64\x8b\x0d\x30\x00\x00\x00/ nocase
        $shellcode3 = /\x64\x8b\x15\x30\x00\x00\x00/ nocase
        $shellcode4 = /\x64\x8b\x35\x30\x00\x00\x00/ nocase
        $shellcode5 = /\x64\x8b\x3d\x30\x00\x00\x00/ nocase
        $shellcode6 = /\xeb\x3c\x5b\x31\xc0\x50\x54\x5a\x83\xec\x64/ nocase
        $shellcode7 = /\xe8\xff\xff\xff\xff\xc1\x5e\x30\x4c\x0e\x07\xe2\xfa/ nocase

        // Suspicious file extensions
        $file_ext1 = ".exe"
        $file_ext2 = ".dll"
        $file_ext3 = ".scr"
        $file_ext4 = ".pif"
        $file_ext5 = ".hta"
        $file_ext6 = ".jar"
        $file_ext7 = ".vbs"
        $file_ext8 = ".wsf"

        // Exploit Kit specific patterns
        $ek1 = "Angler Exploit Kit" nocase
        $ek2 = "Neutrino Exploit Kit" nocase
        $ek3 = "Nuclear Exploit Kit" nocase
        $ek4 = "Rig Exploit Kit" nocase
        $ek5 = "Blackhole Exploit Kit" nocase
        $ek6 = "Magnitude Exploit Kit" nocase
        $ek7 = "Fiesta Exploit Kit" nocase
        $ek8 = "Sweet Orange Exploit Kit" nocase

        // Suspicious network indicators
        $net1 = "http://*exploit*" nocase
        $net2 = "http://*malware*" nocase
        $net3 = "http://*kit*" nocase
        $net4 = "*tor2web*" nocase
        $net5 = "*onion*" nocase

    condition:
        (3 of ($obf_js*) and 3 of ($sus_func*)) or
        4 of ($shellcode*) or
        3 of ($file_ext*) or
        any of ($ek*) or
        2 of ($net*)
}

rule MaliciousFileExtension {
    meta:
        description = "Radical rule for detecting malicious file extensions in Ubuntu/Linux"
        author = "ks"
        date = "2024-05-27"
        version = "4.0"
        reference = "https://example.com/malicious_file_extensions"

    strings:
        // Executable file extensions
        $exe_ext1 = ".elf"
        $exe_ext2 = ".bin"
        $exe_ext3 = ".out"
        $exe_ext4 = ".run"
        $exe_ext5 = ".sh"
        $exe_ext6 = ".bash"
        $exe_ext7 = ".csh"
        $exe_ext8 = ".ksh"
        $exe_ext9 = ".zsh"

        // Library and plugin file extensions
        $lib_ext1 = ".so"
        $lib_ext2 = ".a"
        $lib_ext3 = ".la"
        $lib_ext4 = ".o"
        $lib_ext5 = ".ko"

        // Script file extensions
        $script_ext1 = ".py"
        $script_ext2 = ".pyc"
        $script_ext3 = ".pyo"
        $script_ext4 = ".pyw"
        $script_ext5 = ".pyd"
        $script_ext6 = ".rb"
        $script_ext7 = ".pl"
        $script_ext8 = ".php"
        $script_ext9 = ".js"
        $script_ext10 = ".lua"

        // Document file extensions (can be used for exploits)
        $doc_ext1 = ".doc"
        $doc_ext2 = ".docm"
        $doc_ext3 = ".docx"
        $doc_ext4 = ".xls"
        $doc_ext5 = ".xlsm"
        $doc_ext6 = ".xlsx"
        $doc_ext7 = ".ppt"
        $doc_ext8 = ".pptm"
        $doc_ext9 = ".pptx"
        $doc_ext10 = ".pdf"
        $doc_ext11 = ".rtf"

    condition:
        filesize < 15MB and
        (
            any of ($exe_ext*) or
            any of ($lib_ext*) or
            any of ($script_ext*) or
            any of ($doc_ext*)
        )
}

rule SuspiciousProcessInjection {
    meta:
        description = "Detects suspicious process injection techniques in Ubuntu"
        author = "ks"
        date = "2024-05-27"
        version = "1.0"
        reference = "https://example.com/suspicious_process_injection_ubuntu"

    strings:
        // Linux system calls and functions commonly used for process injection
        $api1 = "ptrace"
        $api2 = "process_vm_writev"
        $api3 = "process_vm_readv"
        $api4 = "memcpy"
        $api5 = "mmap"
        $api6 = "dlopen"
        $api7 = "dlsym"
        $api8 = "LD_PRELOAD"

        // Suspicious process names or substrings in Ubuntu
        $proc1 = "systemd"
        $proc2 = "init"
        $proc3 = "bash"
        $proc4 = "ssh"
        $proc5 = "apache2"
        $proc6 = "nginx"
        $proc7 = "mysql"
        $proc8 = "postgres"

        // Suspicious command-line arguments or patterns
        $cmd1 = /inject/i
        $cmd2 = /ptrace/i
        $cmd3 = /memcpy/i
        $cmd4 = /mmap/i
        $cmd5 = /dlopen/i
        $cmd6 = /LD_PRELOAD/i

    condition:
        // Check for the presence of at least 2 suspicious API functions or system calls
        2 of ($api*) and
        // Check for the presence of at least 1 suspicious process name or substring
        1 of ($proc*) and
        // Check for the presence of at least 1 suspicious command-line argument or pattern
        1 of ($cmd*) and
        // Limit the file size to 5MB for performance considerations
        filesize < 5MB
}
