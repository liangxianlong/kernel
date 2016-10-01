#![feature(asm)]
#![feature(naked_functions)]
#![feature(core_intrinsics)]
#![no_std]

extern crate x86;
extern crate pic;

use x86::shared::dtables;
use x86::shared::dtables::DescriptorTablePointer;
use x86::bits64::irq::IdtEntry;

use core::intrinsics;

static mut IDT: [IdtEntry; 256] = [IdtEntry::MISSING; 256];

pub struct IdtRef {
    ptr: DescriptorTablePointer<IdtEntry>,
    idt: &'static [IdtEntry; 256],
}

impl IdtRef {
    fn set_entry(&mut self, number: usize, body: fn()) {
        let body = body as usize;
        #[naked]
        unsafe extern fn name() {
            asm!("push rbp
                  push r15
                  push r14
                  push r13
                  push r12
                  push r11
                  push r10
                  push r9
                  push r8
                  push rsi
                  push rdi
                  push rdx
                  push rcx
                  push rbx
                  push rax
                  mov rsi, rsp
                  push rsi
                  
                  call $0
                  add rsp, 8
                  pop rax
                  pop rbx
                  pop rcx
                  pop rdx
                  pop rdi
                  pop rsi
                  pop r8
                  pop r9
                  pop r10
                  pop r11
                  pop r12
                  pop r13
                  pop r14
                  pop r15
                  pop rbp
                  iretq" :: "s"(body as fn()) :: "volatile", "intel");
            intrinsics::unreachable();
        }

        use x86::shared::paging::VAddr;
        use x86::shared::PrivilegeLevel;

        let handler = VAddr::from_usize(name as usize);

        // last is "block", idk
        let entry = IdtEntry::new(handler, 0x8, PrivilegeLevel::Ring0, false);

        self.idt[number] = entry;
    }
}

pub fn idt_ref() -> IdtRef {
	// accessing the static mut idt
	let mut r = unsafe {
		IdtRef {
			ptr: DescriptorTablePointer::new_idtp(&IDT[..]),
            idt: &IDT,
		}
	};

	fn isr13() {
		panic!("omg GPF");
	};

    fn isr32() {
        pic::eoi_for(32);

        unsafe {
            x86::shared::irq::enable();
        }
    };

    r.set_entry(13, isr13);
    r.set_entry(32, isr32);

    // this block is safe because we've constructed a proper IDT above.
    unsafe {
        dtables::lidt(&r.ptr)
    };

    r
}

impl IdtRef {
    pub fn enable_interrupts(&self) {
        // This unsafe fn is okay becuase, by virtue of having an IdtRef, we know that we have a
        // valid Idt.
        unsafe {
            x86::shared::irq::enable();
        }
    }
}

