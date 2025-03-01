function getWindowStyleFlags(style) {
    const flags = [];
    const WS = {
        0x80000000: 'WS_POPUP',
        0x40000000: 'WS_CHILD',
        0x20000000: 'WS_MINIMIZE',
        0x10000000: 'WS_VISIBLE',
        0x00C00000: 'WS_CAPTION',
        0x00800000: 'WS_BORDER',
        0x00400000: 'WS_DLGFRAME',
        0x00200000: 'WS_VSCROLL',
        0x00100000: 'WS_HSCROLL',
        0x00080000: 'WS_SYSMENU',
        0x00040000: 'WS_THICKFRAME',
        0x00020000: 'WS_MINIMIZEBOX',
        0x00010000: 'WS_MAXIMIZEBOX',
		0x00000001: 'WS_EX_DLGMODALFRAME',
        0x00000008: 'WS_EX_TOPMOST',
        0x00000040: 'WS_EX_TOOLWINDOW',
        0x00000100: 'WS_EX_WINDOWEDGE',
        0x00000200: 'WS_EX_CLIENTEDGE',
        0x00000400: 'WS_EX_CONTEXTHELP',
        0x00080000: 'WS_EX_LAYERED',
        0x02000000: 'WS_EX_COMPOSITED'
    };

    for (const [flag, name] of Object.entries(WS)) {
        if (style & parseInt(flag)) flags.push(name);
    }
    return flags.join(' | ');
}

// https://www.autoitscript.com/autoit3/docs/appendix/WinMsgCodes.htm
function getMessageName(msg) {
    const messages = {
        0x0001: 'WM_CREATE',
        0x0002: 'WM_DESTROY',
        0x0111: 'WM_COMMAND',
        0x0112: 'WM_HSCROLL',
        0x0113: 'WM_VSCROLL',
		0x000C: "WM_SETTEXT",
        0x000D: "WM_GETTEXT",
        0x000F: "WM_PAINT",
        0x0010: "WM_CLOSE",
        0x0100: "WM_KEYDOWN",
        0x0101: "WM_KEYUP",
        0x0102: "WM_CHAR",
		0x0003: 'WM_MOVE',
		0x0005: 'WM_SIZE',
		0x0006: 'WM_ACTIVATE',
		0x0018: 'WM_SHOWWINDOW',
		0x0082: 'WM_NCCREATE',
		0x00A0: 'WM_NCMOUSEMOVE',
		0x011F: 'WM_CTLCOLOR',
		0x0118: 'WM_SYSCOMMAND',
		0x0400: 'WM_USER',
        0x0081: 'WM_NCCREATE',
        0x0024: 'WM_GETMINMAXINFO',
        0x0083: 'WM_NCCALCSIZE',
        0x0024: 'WM_WINDOWPOSCHANGING',
        0x001c: 'WM_ACTIVATEAPP',
        0x0055: 'WM_NOTIFYFORMAT',
        0x0031: 'WM_GETFONT',
        0x0281: 'WM_IME_SETCONTEXT',
        0x0282: 'WM_IME_NOTIFY',
        0x0007: 'WM_SETFOCUS',
        0x0047: 'WM_HANDHELDLAST',
        0x0086: 'WM_NCACTIVATE',
    };
    return messages[msg] || `0x${msg.toString(16)}`;
}

function getClassStyleFlags(style) {
    const CS = {
        0x0001: 'CS_VREDRAW',
        0x0002: 'CS_HREDRAW',
        0x0008: 'CS_DBLCLKS',
        0x0020: 'CS_OWNDC',
        0x0080: 'CS_CLASSDC',
        0x0004: 'CS_NOCLOSE'
    };
    return resolveFlags(style, CS);
}

function getAllocType(flags) {
    const types = [];
    const ALLOC = {
        0x1000: 'MEM_COMMIT',
        0x2000: 'MEM_RESERVE',
        0x10000: 'MEM_FREE'
    };
    
    for (const [flag, name] of Object.entries(ALLOC)) {
        if (flags & flag) types.push(name);
    }
    return types.join(' | ');
}

function getProtectionFlags(flags) {
    const prot = {
        0x01: 'PAGE_NOACCESS',
        0x02: 'PAGE_READONLY',
        0x04: 'PAGE_READWRITE',
        0x08: 'PAGE_WRITECOPY',
        0x10: 'PAGE_EXECUTE',
        0x20: 'PAGE_EXECUTE_READ',
        0x40: 'PAGE_EXECUTE_READWRITE',
        0x80: 'PAGE_EXECUTE_WRITECOPY'
    };
    return prot[flags] || `${flags.toString(16)}`;
}

const { log } = console;

function getWindowText(hWnd) {
    if (hWnd.isNull()) return 'NULL';
    try {
        const fnGetWindowTextW = new NativeFunction(
            Module.getExportByName('user32.dll', 'GetWindowTextW'),
            'int', ['pointer', 'pointer', 'int']
        );
        const buffer = Memory.alloc(512);
        const result = fnGetWindowTextW(hWnd, buffer, 256);
        return result > 0 ? buffer.readUtf16String() : '<no title>';
    } catch(e) {
        return `<error: ${e}>`;
    }
}

function hookSendPostMessage(funcName) {
    Interceptor.attach(Module.getExportByName('user32.dll', funcName), {
        onEnter: function(args) {
            const hWnd = args[0];
            const Msg = args[1].toInt32();
            const wParam = args[2].toInt32();
            const lParam = args[3].toString();
            
            log(`\n----- [${funcName}] -----`);
            log(` | hWnd: ${hWnd} | Msg: ${getMessageName(Msg)}`);
            log(` | wParam: ${wParam.toString(16)} | lParam: ${lParam}`);
            
            // checking message data for the large buffers seen in the routine
            if (!args[3].isNull() && lParam !== '0x0') {
                try {
                    let bufferSize = 4096; 
                    const buf = args[3].readByteArray(bufferSize);
                    log(` | Size: ${bufferSize}`);
                    log(" | Data: " + hexdump(buf, { offset: 0, length: 4096, header: false, ansi: false }));
                } catch(e) {
                    log(` | [X] Failed to read buffer: ${e}`);
                }
            }
        }
    });
}

function resolveFlags(value, flagDict) {
    let flags = [];
    for (let key in flagDict) {
        if (value & parseInt(key)) {
            flags.push(flagDict[key]);
        }
    }
    return flags.length > 0 ? flags.join(" | ") : "None";
}

hookSendPostMessage('SendMessageW');
hookSendPostMessage('PostMessageW');

Interceptor.attach(Module.getExportByName('user32.dll', 'RegisterClassW'), {
    onEnter: function (args) {
        console.log("\n----- [RegisterClassW] -----");
        const wcPtr = args[0];

        if (wcPtr.isNull()) {
            console.log("RegisterClassW: NULL lpWndClass");
            return;
        }
        
        // read the WNDCLASS struct
        try {
            let style = wcPtr.add(0).readU32();
            let lpfnWndProc = wcPtr.add(4).readPointer();
            let cbClsExtra = wcPtr.add(8).readU32();
            let cbWndExtra = wcPtr.add(12).readU32();
            let hInstance = wcPtr.add(16).readPointer();
            let hIcon = wcPtr.add(20).readPointer();
            let hCursor = wcPtr.add(24).readPointer();
            let hbrBackground = wcPtr.add(28).readPointer();
            let lpszMenuNamePtr = wcPtr.add(32).readPointer();
            let lpszClassNamePtr = wcPtr.add(36).readPointer();

            console.log(` | style: ${style.toString(16)} -> ${getClassStyleFlags(style)}`);
            console.log(` | lpfnWndProc: ${lpfnWndProc}`);
            console.log(` | cbClsExtra: ${cbClsExtra}`);
            console.log(` | cbWndExtra: ${cbWndExtra}`);
            console.log(` | hInstance: ${hInstance}`);
            console.log(` | hIcon: ${hIcon}`);
            console.log(` | hCursor: ${hCursor}`);
            console.log(` | hbrBackground: ${hbrBackground}`);
			
            let menuName = lpszMenuNamePtr.isNull() ? "NULL" : lpszMenuNamePtr.readUtf16String();
            console.log(` | lpszMenuName: ${menuName}`);

            let className = lpszClassNamePtr.isNull() ? "NULL" : lpszClassNamePtr.readUtf16String();
            console.log(` | lpszClassName: ${className}`);

        } catch (e) {
            console.log(` | [X] Failed to read WNDCLASS: ${e}`);
        }
    }
});

Interceptor.attach(Module.getExportByName('user32.dll', 'CreateWindowExW'), {
    onEnter: function (args) {
		log("\n----- [CreateWindowExW] -----");
		if (!hWndParent.isNull()) {
			log(` | hWndParent: ${args[8]} (${getWindowText(args[8])})`);
		}
        log(` | dwExStyle: ${args[0].toInt32().toString(16)}`);
        log(` | lpClassName: ${args[1].isNull() ? 'NULL' : args[1].readUtf16String()}`);
        log(` | lpWindowName: ${args[2].isNull() ? 'NULL' : args[2].readUtf16String()}`);
        log(` | dwStyle: ${args[3].toInt32().toString(16)} -> ${getWindowStyleFlags(args[3].toInt32())}`);
        log(` | X: ${args[4].toInt32()} | Y: ${args[5].toInt32()}`);
        log(` | nWidth: ${args[6].toInt32()} | nHeight: ${args[7].toInt32()}`);
        log(` | hMenu: ${args[9].toString()}`);
        log(` | hInstance: ${args[10].toString()}`);
        log(` | lpParam: ${args[11].toString()}`);
    }
});

Interceptor.attach(Module.getExportByName('user32.dll', 'DefWindowProcW'), {
    onEnter: function (args) {
        log("\n----- [DefWindowProcW] -----");
        log(` | hWnd: ${args[0].toString()}`);
        log(` | uMsg: ${getMessageName(args[1].toInt32())}`);
        log(` | wParam: ${args[2].toInt32().toString(16)}`);
        log(` | lParam: ${args[3].toString()}`);
    },
    onLeave: function (retval) {
        log(`Return value: ${retval.toString()}`);
    }
});

Interceptor.attach(Module.findExportByName("user32.dll", "DispatchMessageW"), {
    onEnter: function (args) {
        log("\n----- [DispatchMessage] -----")
        var msgPtr = args[0];  // ptr to MSG struct
        var hwnd = msgPtr.add(0).readPointer();  
        var message = msgPtr.add(4).readU32();  
        var wParam = msgPtr.add(8).readU32();    
        var lParam = msgPtr.add(12).readU32();   
        var msgName = getMessageName(message);
        
        log(" | hWnd: " + hwnd.toInt32() + 
            " | Message: " + msgName + 
            " | wParam: " + wParam.toString(16) + 
            " | lParam: " + lParam.toString(16));
    }
});

Interceptor.attach(Module.getExportByName('user32.dll', 'ShowWindow'), {
    onEnter: function (args) {
        log("\n----- [ShowWindow] -----")
        const cmd = args[1].toInt32();

        log(' | hWnd:', args[0]);
		log(' | nCmdShow:', cmd.toString(16));
    }
});

Interceptor.attach(Module.getExportByName('kernel32.dll', 'VirtualAlloc'), {
    onEnter: function (args) {
        log("\n----- [VirtualAlloc] -----");
        log(` | lpAddress: ${args[0].toString()}`);
        log(` | dwSize: ${args[1].toInt32()} bytes`);
        log(` | flAllocationType: ${getAllocType(args[2].toInt32())}`);
        log(` | flProtect: ${getProtectionFlags(args[3].toInt32())}`);
    },
    onLeave: function (retval) {
        log(` | Allocated at: ${retval.toString()}`);
    }
});

Interceptor.attach(Module.getExportByName('kernel32.dll', 'CreateFile'), {
    onEnter: function (args) {
        log("\n----- [CreateFile] -----")
        var fileName = args[0].readAnsiString();
        log(" | Name: " + fileName);
    }
});

Interceptor.attach(Module.getExportByName('kernel32.dll', 'ReadFile'), {
    onEnter: function (args) {
        log("\n----- [ReadFile] -----")
        this.hFile = args[0];
        this.buff = args[1];
        this.bytesToRead = args[2].toInt32();
    },
    onLeave: function(retval) {
        if (retval.toInt32() > 0) {
            log(" | Read: " + this.buff.readAnsiString(this.bytesToRead));
        }
    }
});

// can dump decrypted main module
Interceptor.attach(Module.getExportByName('ntdll.dll', 'ZwWriteVirtualMemory'), {
    onEnter: function(args) {
        log('\n----- [ZwWriteVirtualMemory] -----');
        this.processHandle = args[0];
        this.baseAddress = args[1];
        this.buffer = args[2];
        this.size = args[3].toInt32();
        
        log(` | Target Process: ${this.processHandle}`);
        log(` | Write Address: ${this.baseAddress}`);
        log(` | Buffer Size: ${this.size} bytes`);
        
        // peak buffer
        if (this.size > 0) {
            const dump = this.buffer.readByteArray(this.size);
            log(hexdump(dump, { offset: 0, length: 64, header: false, ansi: false }));
        }
    }
});