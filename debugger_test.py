import pydebugger


def dump_registers(debugger):
    thread_list = debugger.enumerate_threads()

    for thread in thread_list:

        thread_context = debugger.get_thread_context(thread)

        print "[*] Dumping registers for thread ID: 0x%08x" % thread
        print "[**] EIP: 0x%08x" % thread_context.Eip
        print "[**] ESP: 0x%08x" % thread_context.Esp
        print "[**] EBP: 0x%08x" % thread_context.Ebp
        print "[**] EAX: 0x%08x" % thread_context.Eax
        print "[**] EBX: 0x%08x" % thread_context.Ebx
        print "[**] ECX: 0x%08x" % thread_context.Ecx
        print "[**] EDX: 0x%08x" % thread_context.Edx
        print "[*] END DUMP"


def main():

    debugger = pydebugger.PyDebugger()

    #the_debugger.load("C:\\Windows\\system32\\calc.exe")
    pid = raw_input("Enter the PID of the process to attach to: ")

    debugger.attach(int(pid))

    dump_registers(debugger)

    debugger.run()

    debugger.detach()

if __name__ == "__main__":
    main()