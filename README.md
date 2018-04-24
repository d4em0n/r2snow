# r2snow

This script help you decompiling in radare2 using snowman decompiler.

```
[0x00400520]> #!pipe /home/ramdhan/scripts/r2snow/r2decompiler.py -l
]- deregister_tm_clones
]- register_tm_clones
]- __do_global_dtors_aux
]- frame_dummy
]- __libc_csu_fini
]- puts@@GLIBC_2.2.5
]- _fini
]- printf@@GLIBC_2.2.5
]- __libc_start_main@@GLIBC_2.2.5
]- fgets@@GLIBC_2.2.5
]- strcmp@@GLIBC_2.2.5
]- __libc_csu_init
]- _dl_relocate_static_pie
]- _start
]- main
]- _init
]- puts
]- printf
]- __libc_start_main
]- fgets
]- strcmp
]- fun_4004e0
]- fun_4004f0
]- fun_400500
]- fun_400510
]- fun_4005c5
]- fun_4005eb
]- fun_40058a
]- fun_4004e6
]- fun_4004f6
]- fun_400506
]- fun_400516
[0x00400520]> #!pipe /home/ramdhan/scripts/r2snow/r2decompiler.py -f main
int64_t main() {
    void* rbp1;
    int64_t rdx2;
    int32_t eax3;

    rbp1 = reinterpret_cast<void*>(reinterpret_cast<int64_t>(__zero_stack_offset()) - 8);
    fun_4004f0("Enter password : ");
    rdx2 = stdin;
    fun_400500(reinterpret_cast<int64_t>(rbp1) - 32, 19, rdx2);
    eax3 = fun_400510(reinterpret_cast<int64_t>(rbp1) - 32, "hax0rs31337", rdx2);
    if (eax3) {
        fun_4004e0("Noob", "hax0rs31337", rdx2);
    } else {
        fun_4004e0("You are haxor", "hax0rs31337", rdx2);
    }
    return 0;
}
```